//! C ABI for embedding the Spectre engine.
//!
//! Design: a handful of coarse-grained functions exchanging UTF-8 JSON. UniFFI
//! was evaluated; for an API this coarse it would add a code-generation step
//! and generated Swift sources without a meaningful safety gain over a small,
//! audited C surface (see `docs/architecture.md`).
//!
//! Every returned `char *` is owned by the caller and must be released with
//! [`spectre_string_free`]. Responses are envelopes:
//! `{"ok": <value>}` or `{"error": {"code": "...", "message": "..."}}`.
//!
//! All functions are safe to call from any thread, and none may be called
//! from inside an async runtime thread. Blocking calls are expected to run on
//! a background thread in the host application.

use std::ffi::{CStr, CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Once};
use std::time::Duration;

use serde_json::{Value, json};
use spectre_core::error::{ErrorCode, SpectreError};
use spectre_discovery::{Engine, EngineConfig, EngineOptions};
use zeroize::Zeroizing;

/// Opaque engine handle.
pub struct SpectreEngine {
    runtime: tokio::runtime::Runtime,
    engine: Arc<Engine>,
}

static LOGGING: Once = Once::new();

fn init_logging() {
    LOGGING.call_once(|| {
        let filter =
            tracing_subscriber::EnvFilter::try_from_env("SPECTRE_LOG").unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
        let _ = tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).with_target(false).try_init();
    });
}

fn envelope(result: Result<Value, SpectreError>) -> *mut c_char {
    let body = match result {
        Ok(value) => json!({ "ok": value }),
        Err(error) => json!({ "error": { "code": error.code, "message": error.message } }),
    };
    into_c_string(body.to_string())
}

fn into_c_string(text: String) -> *mut c_char {
    // JSON never contains interior NULs; fall back defensively anyway.
    CString::new(text)
        .unwrap_or_else(|_| CString::new(r#"{"error":{"code":"internal","message":"invalid response"}}"#).expect("static"))
        .into_raw()
}

/// # Safety
/// `pointer` must be null or a valid NUL-terminated string.
unsafe fn read_str<'a>(pointer: *const c_char) -> Result<&'a str, SpectreError> {
    if pointer.is_null() {
        return Err(SpectreError::invalid_input("null string argument"));
    }
    // SAFETY: the caller guarantees a valid NUL-terminated string.
    unsafe { CStr::from_ptr(pointer) }.to_str().map_err(|_| SpectreError::invalid_input("argument is not valid UTF-8"))
}

fn guarded(operation: impl FnOnce() -> Result<Value, SpectreError>) -> *mut c_char {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(result) => envelope(result),
        Err(_) => envelope(Err(SpectreError::new(ErrorCode::Internal, "engine panicked; the operation was aborted"))),
    }
}

/// Create an engine. `options_json` may be null or `{"database_path": "..."}`.
/// Returns null on failure and, if `error_out` is non-null, stores an error
/// envelope there (free it with [`spectre_string_free`]).
///
/// # Safety
/// `options_json` must be null or a valid NUL-terminated UTF-8 string.
/// `error_out` must be null or point to writable storage for one pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spectre_engine_open(options_json: *const c_char, error_out: *mut *mut c_char) -> *mut SpectreEngine {
    init_logging();
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<SpectreEngine, SpectreError> {
        let options: EngineOptions = if options_json.is_null() {
            EngineOptions::default()
        } else {
            // SAFETY: forwarded caller guarantee.
            let raw = unsafe { read_str(options_json) }?;
            serde_json::from_str(raw).map_err(|error| SpectreError::invalid_input(format!("invalid options: {error}")))?
        };
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .thread_name("spectre-engine")
            .enable_all()
            .build()
            .map_err(|error| SpectreError::internal(format!("failed to start runtime: {error}")))?;
        let config = EngineConfig { database_path: options.database_path.map(Into::into), ..Default::default() };
        let engine = runtime.block_on(Engine::open(config))?;
        Ok(SpectreEngine { runtime, engine })
    }));
    let outcome = result.unwrap_or_else(|_| Err(SpectreError::internal("engine panicked during startup")));
    match outcome {
        Ok(engine) => Box::into_raw(Box::new(engine)),
        Err(error) => {
            if !error_out.is_null() {
                // SAFETY: caller guarantees `error_out` is writable.
                unsafe { *error_out = envelope(Err(error)) };
            }
            std::ptr::null_mut()
        }
    }
}

/// Cancel running work, close storage, and free the engine.
///
/// # Safety
/// `engine` must be null or a pointer returned by [`spectre_engine_open`]
/// that has not been closed. No other call may be in flight.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spectre_engine_close(engine: *mut SpectreEngine) {
    if engine.is_null() {
        return;
    }
    // SAFETY: caller transfers ownership of a pointer from `spectre_engine_open`.
    let handle = unsafe { Box::from_raw(engine) };
    let _ = catch_unwind(AssertUnwindSafe(|| {
        handle.runtime.block_on(handle.engine.shutdown());
    }));
    let SpectreEngine { runtime, engine } = *handle;
    drop(engine);
    runtime.shutdown_timeout(Duration::from_secs(2));
}

/// Invoke a JSON API method. Blocks until the method completes.
///
/// # Safety
/// `engine` must be a live handle; `method` and `params_json` must be valid
/// NUL-terminated UTF-8 strings (`params_json` may be null for `{}`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spectre_engine_call(
    engine: *const SpectreEngine,
    method: *const c_char,
    params_json: *const c_char,
) -> *mut c_char {
    guarded(|| {
        // SAFETY: caller guarantees a live handle.
        let handle = unsafe { engine.as_ref() }.ok_or_else(|| SpectreError::invalid_input("null engine"))?;
        // SAFETY: forwarded caller guarantees.
        let method = unsafe { read_str(method) }?;
        let parameters: Value = if params_json.is_null() {
            json!({})
        } else {
            // SAFETY: forwarded caller guarantee.
            let raw = unsafe { read_str(params_json) }?;
            serde_json::from_str(raw).map_err(|error| SpectreError::invalid_input(format!("params are not valid JSON: {error}")))?
        };
        handle.runtime.block_on(handle.engine.call(method, parameters))
    })
}

/// Wait up to `timeout_ms` for investigation events and return a batch:
/// `{"events": [...], "finished": bool, "unknown": bool}`.
///
/// # Safety
/// `engine` must be a live handle and `investigation_id` a valid
/// NUL-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spectre_engine_poll_events(
    engine: *const SpectreEngine,
    investigation_id: *const c_char,
    max_events: u32,
    timeout_ms: u32,
) -> *mut c_char {
    guarded(|| {
        // SAFETY: caller guarantees a live handle.
        let handle = unsafe { engine.as_ref() }.ok_or_else(|| SpectreError::invalid_input("null engine"))?;
        // SAFETY: forwarded caller guarantee.
        let identifier = unsafe { read_str(investigation_id) }?;
        let identifier = uuid::Uuid::parse_str(identifier).map_err(|_| SpectreError::invalid_input("invalid investigation id"))?;
        let batch = handle.engine.events().wait(identifier, max_events as usize, Duration::from_millis(u64::from(timeout_ms.min(5_000))));
        serde_json::to_value(batch).map_err(|error| SpectreError::internal(error.to_string()))
    })
}

/// Check a password against Pwned Passwords using k-anonymity. The bytes are
/// copied into zeroizing memory; the caller should wipe its own buffer.
///
/// # Safety
/// `engine` must be a live handle; `password` must point to `length`
/// readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spectre_check_password(engine: *const SpectreEngine, password: *const u8, length: usize) -> *mut c_char {
    guarded(|| {
        // SAFETY: caller guarantees a live handle.
        let handle = unsafe { engine.as_ref() }.ok_or_else(|| SpectreError::invalid_input("null engine"))?;
        if password.is_null() || length == 0 {
            return Err(SpectreError::invalid_input("password is empty"));
        }
        // SAFETY: caller guarantees `length` readable bytes at `password`.
        let bytes = Zeroizing::new(unsafe { std::slice::from_raw_parts(password, length) }.to_vec());
        let result = handle.runtime.block_on(handle.engine.check_password(bytes))?;
        serde_json::to_value(result).map_err(|error| SpectreError::internal(error.to_string()))
    })
}

/// Free a string returned by this library.
///
/// # Safety
/// `value` must be null or a pointer returned by this library, freed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spectre_string_free(value: *mut c_char) {
    if !value.is_null() {
        // SAFETY: caller returns ownership of a pointer from `CString::into_raw`.
        drop(unsafe { CString::from_raw(value) });
    }
}

/// Static, NUL-terminated version string. Do not free.
#[unsafe(no_mangle)]
pub extern "C" fn spectre_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn take(pointer: *mut c_char) -> Value {
        assert!(!pointer.is_null());
        // SAFETY: pointer comes from this library.
        let text = unsafe { CStr::from_ptr(pointer) }.to_str().unwrap().to_string();
        // SAFETY: freeing our own allocation exactly once.
        unsafe { spectre_string_free(pointer) };
        serde_json::from_str(&text).unwrap()
    }

    #[test]
    fn round_trip_through_the_c_abi() {
        let directory = tempfile::tempdir().unwrap();
        let options = CString::new(json!({ "database_path": directory.path().join("ffi.sqlite") }).to_string()).unwrap();
        let mut error = std::ptr::null_mut();
        // SAFETY: valid arguments.
        let engine = unsafe { spectre_engine_open(options.as_ptr(), &mut error) };
        assert!(!engine.is_null() && error.is_null());

        let method = CString::new("target.validate").unwrap();
        let params = CString::new(r#"{"target_type":"email","value":"Alice@Example.COM"}"#).unwrap();
        // SAFETY: live engine and valid strings.
        let response = take(unsafe { spectre_engine_call(engine, method.as_ptr(), params.as_ptr()) });
        assert_eq!(response["ok"]["normalized"], "alice@example.com");

        let unknown = CString::new("nope").unwrap();
        // SAFETY: live engine and valid strings; null params means {}.
        let response = take(unsafe { spectre_engine_call(engine, unknown.as_ptr(), std::ptr::null()) });
        assert_eq!(response["error"]["code"], "invalid_input");

        let bad_json = CString::new("{not json").unwrap();
        // SAFETY: as above.
        let response = take(unsafe { spectre_engine_call(engine, method.as_ptr(), bad_json.as_ptr()) });
        assert_eq!(response["error"]["code"], "invalid_input");

        let identifier = CString::new(uuid::Uuid::new_v4().to_string()).unwrap();
        // SAFETY: live engine and valid string.
        let batch = take(unsafe { spectre_engine_poll_events(engine, identifier.as_ptr(), 10, 10) });
        assert_eq!(batch["ok"]["unknown"], true);

        // SAFETY: empty password is rejected before any network use.
        let response = take(unsafe { spectre_check_password(engine, std::ptr::null(), 0) });
        assert_eq!(response["error"]["code"], "invalid_input");

        // SAFETY: static string.
        let version = unsafe { CStr::from_ptr(spectre_version()) }.to_str().unwrap();
        assert_eq!(version, env!("CARGO_PKG_VERSION"));
        // SAFETY: closing a live engine once.
        unsafe { spectre_engine_close(engine) };
    }

    #[test]
    fn open_reports_errors() {
        let options = CString::new("{bad").unwrap();
        let mut error = std::ptr::null_mut();
        // SAFETY: valid pointers.
        let engine = unsafe { spectre_engine_open(options.as_ptr(), &mut error) };
        assert!(engine.is_null());
        assert_eq!(take(error)["error"]["code"], "invalid_input");
    }
}

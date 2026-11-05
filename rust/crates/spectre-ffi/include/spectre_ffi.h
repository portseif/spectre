/*
 * Spectre engine C ABI.
 *
 * All strings are UTF-8 and NUL-terminated. Every `char *` returned by this
 * library is owned by the caller and must be released with
 * spectre_string_free(). Responses are JSON envelopes:
 *   {"ok": <value>}  or  {"error": {"code": "<code>", "message": "<text>"}}
 *
 * Functions block; call them from a background thread, never the UI thread.
 */
#ifndef SPECTRE_FFI_H
#define SPECTRE_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SpectreEngine SpectreEngine;

/* Open an engine. options_json may be NULL or {"database_path": "..."}.
 * Returns NULL on failure; *error_out (if non-NULL) receives an error envelope. */
SpectreEngine *spectre_engine_open(const char *options_json, char **error_out);

/* Cancel running work, close storage, free the handle. */
void spectre_engine_close(SpectreEngine *engine);

/* Invoke a JSON API method (see docs/architecture.md). params_json may be NULL. */
char *spectre_engine_call(const SpectreEngine *engine, const char *method, const char *params_json);

/* Wait up to timeout_ms (max 5000) for investigation events. */
char *spectre_engine_poll_events(const SpectreEngine *engine, const char *investigation_id, uint32_t max_events, uint32_t timeout_ms);

/* Pwned Passwords k-anonymity check. Only a 5-character SHA-1 prefix leaves
 * the device. The caller should zero its buffer afterwards. */
char *spectre_check_password(const SpectreEngine *engine, const uint8_t *password, size_t length);

void spectre_string_free(char *value);

/* Static version string; do not free. */
const char *spectre_version(void);

#ifdef __cplusplus
}
#endif

#endif /* SPECTRE_FFI_H */

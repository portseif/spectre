//! `spectre`, the command-line interface to the Spectre engine.
//!
//! Credentials come from the environment (never from arguments):
//! `SPECTRE_HIBP_API_KEY`, `SPECTRE_GITHUB_TOKEN`. The database defaults to
//! `~/Library/Application Support/Spectre/cli.sqlite` (override with
//! `--db PATH` or `SPECTRE_DB`; `--db :memory:` for a throwaway run).

use std::io::{BufRead, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use spectre_core::credentials::ids;
use spectre_core::model::{FindingData, InvestigationEventKind, InvestigationStatus};
use spectre_core::target::TargetType;
use spectre_discovery::{Engine, EngineConfig, StartInvestigationRequest};
use uuid::Uuid;
use zeroize::Zeroizing;

const USAGE: &str = "\
spectre: authorized OSINT investigations

USAGE:
    spectre [--db PATH] [--json] <command> [args]

COMMANDS:
    investigate <username|email|phone|domain> <value> --purpose TEXT [--providers a,b] [--region CC]
    list [search]                     List stored investigations
    show <id>                         Show an investigation's findings and graph summary
    export <id> --format json|csv     Export an investigation
    providers                         List providers and their configuration
    password-check                    Read one password from stdin; k-anonymity check
    hash-inventory <file|->           Inventory hash storage schemes (authorized admins)
    breach-catalog [--refresh] [search]
    follow-ups <id>                   Identifiers the findings point to (start each one yourself)
    sites [verify]                    List profile-page checks, or self-test them live
    bench <type> <value> [--runs N]   Run repeated investigations and report metrics
    call <method> [json]              Invoke a raw engine API method
";

struct Options {
    database: Option<PathBuf>,
    json: bool,
    arguments: Vec<String>,
}

fn parse_options() -> Result<Options, String> {
    let mut database = std::env::var("SPECTRE_DB").ok().map(PathBuf::from);
    let mut json = false;
    let mut arguments = Vec::new();
    let mut raw = std::env::args().skip(1);
    while let Some(argument) = raw.next() {
        match argument.as_str() {
            "--db" => database = Some(raw.next().ok_or("--db requires a path")?.into()),
            "--json" => json = true,
            "-h" | "--help" => return Err(String::new()),
            _ => arguments.push(argument),
        }
    }
    if database.is_none()
        && let Ok(home) = std::env::var("HOME")
    {
        database = Some(PathBuf::from(home).join("Library/Application Support/Spectre/cli.sqlite"));
    }
    if database.as_deref().is_some_and(|path| path.as_os_str() == ":memory:") {
        database = None;
    }
    Ok(Options { database, json, arguments })
}

fn flag(arguments: &[String], name: &str) -> Option<String> {
    arguments.iter().position(|argument| argument == name).and_then(|index| arguments.get(index + 1).cloned())
}

fn positional(arguments: &[String]) -> Vec<&str> {
    let mut values = Vec::new();
    let mut skip = false;
    for argument in arguments {
        if skip {
            skip = false;
            continue;
        }
        if argument.starts_with("--") {
            skip = !matches!(argument.as_str(), "--refresh");
            continue;
        }
        values.push(argument.as_str());
    }
    values
}

fn print(value: &Value) {
    println!("{}", serde_json::to_string_pretty(value).unwrap_or_default());
}

async fn open_engine(options: &Options) -> Result<Arc<Engine>, String> {
    let engine = Engine::open(EngineConfig { database_path: options.database.clone(), ..Default::default() })
        .await
        .map_err(|error| error.message)?;
    for (variable, credential) in [("SPECTRE_HIBP_API_KEY", ids::HIBP_API_KEY), ("SPECTRE_GITHUB_TOKEN", ids::GITHUB_TOKEN)] {
        if let Ok(secret) = std::env::var(variable) {
            engine.credentials().set(credential, Zeroizing::new(secret));
        }
    }
    Ok(engine)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Output {
    Human,
    JsonLines,
    Silent,
}

async fn investigate(engine: &Arc<Engine>, arguments: &[String], output: Output) -> Result<Uuid, String> {
    let values = positional(arguments);
    let [target_type, value, ..] = values.as_slice() else { return Err("investigate needs a type and a value".into()) };
    let target_type: TargetType = target_type.parse().map_err(|error: spectre_core::error::SpectreError| error.message)?;
    let purpose = flag(arguments, "--purpose").ok_or("--purpose is required: record the authorization basis and scope")?;
    let request = StartInvestigationRequest {
        target_type,
        value: value.to_string(),
        purpose,
        provider_ids: flag(arguments, "--providers").map(|list| list.split(',').map(str::trim).map(str::to_string).collect()),
        default_region: flag(arguments, "--region"),
    };
    let investigation = engine.start_investigation(request).await.map_err(|error| error.message)?;
    if output == Output::Human {
        println!("Investigation {} · {} · {} provider(s)", investigation.id, investigation.target, investigation.providers.len());
    }
    let identifier = investigation.id;
    let events_engine = Arc::clone(engine);
    let interrupted = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let engine = Arc::clone(engine);
        let interrupted = Arc::clone(&interrupted);
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                interrupted.store(true, std::sync::atomic::Ordering::SeqCst);
                engine.cancel_investigation(identifier);
            }
        });
    }
    loop {
        let engine = Arc::clone(&events_engine);
        let batch = tokio::task::spawn_blocking(move || engine.events().wait(identifier, 64, Duration::from_millis(250)))
            .await
            .map_err(|error| error.to_string())?;
        for event in &batch.events {
            match output {
                Output::Silent => continue,
                Output::JsonLines => {
                    println!("{}", serde_json::to_string(event).unwrap_or_default());
                    continue;
                }
                Output::Human => {}
            }
            match &event.event {
                InvestigationEventKind::FindingDiscovered { finding } => {
                    let detail = match &finding.data {
                        FindingData::Profile(profile) => profile.profile_url.clone(),
                        _ => finding.summary.clone().unwrap_or_default(),
                    };
                    println!("  + [{}] {}: {}", finding.confidence.category.label(), finding.title, detail);
                }
                InvestigationEventKind::ProviderFailed { failure } => {
                    println!("  ! {} failed ({:?}): {}", failure.provider_id, failure.code, failure.message);
                }
                InvestigationEventKind::CorrelationUpdated { identities, relationships } => {
                    println!("  ~ correlated {identities} identities, {relationships} relationships");
                }
                InvestigationEventKind::Finished { status, metrics } => {
                    println!(
                        "Finished: {status:?} in {} ms (startup {} ms, first finding {} ms, {} requests, cache {}/{})",
                        metrics.total_duration_ms,
                        metrics.startup_latency_ms,
                        metrics.time_to_first_finding_ms.map(|value| value.to_string()).unwrap_or_else(|| "none".into()),
                        metrics.http_requests,
                        metrics.cache_hits,
                        metrics.cache_hits + metrics.cache_misses
                    );
                }
                _ => {}
            }
        }
        if batch.finished {
            break;
        }
    }
    if interrupted.load(std::sync::atomic::Ordering::SeqCst) && output == Output::Human {
        println!("Cancelled by user.");
    }
    Ok(identifier)
}

async fn run(options: Options) -> Result<(), String> {
    let Some(command) = options.arguments.first().cloned() else { return Err(String::new()) };
    let rest: Vec<String> = options.arguments[1..].to_vec();
    let engine = open_engine(&options).await?;
    let call = |method: &'static str, parameters: Value| {
        let engine = Arc::clone(&engine);
        async move { engine.call(method, parameters).await.map_err(|error| format!("{:?}: {}", error.code, error.message)) }
    };
    match command.as_str() {
        "investigate" => {
            let identifier = investigate(&engine, &rest, if options.json { Output::JsonLines } else { Output::Human }).await?;
            if !options.json {
                let detail = engine.storage().detail(identifier).await.map_err(|error| error.message)?;
                let mut categories = std::collections::BTreeMap::new();
                for edge in &detail.graph.edges {
                    *categories.entry(edge.category.label()).or_insert(0) += 1;
                }
                println!("Relationships by confidence: {categories:?}");
            }
        }
        "list" => {
            let search = positional(&rest).first().map(|value| value.to_string());
            let listing = call("investigation.list", json!({ "search": search })).await?;
            if options.json {
                print(&listing);
            } else {
                for item in listing.as_array().into_iter().flatten() {
                    println!(
                        "{}  {:<20} {:<9} {:<40} {} findings",
                        item["id"].as_str().unwrap_or_default(),
                        item["status"].as_str().unwrap_or_default(),
                        item["target_type"].as_str().unwrap_or_default(),
                        item["target"]["value"].as_str().unwrap_or_default(),
                        item["findings_count"]
                    );
                }
            }
        }
        "show" => {
            let identifier = positional(&rest).first().copied().ok_or("show needs an investigation id")?.to_string();
            let detail = call("investigation.get", json!({ "id": identifier })).await?;
            if options.json {
                print(&detail);
            } else {
                println!("{} · {}", detail["investigation"]["target"]["value"], detail["investigation"]["status"]);
                for finding in detail["findings"].as_array().into_iter().flatten() {
                    println!(
                        "  [{}] {}",
                        finding["confidence"]["category"].as_str().unwrap_or_default(),
                        finding["title"].as_str().unwrap_or_default()
                    );
                }
            }
        }
        "export" => {
            let identifier = positional(&rest).first().copied().ok_or("export needs an investigation id")?.to_string();
            match flag(&rest, "--format").as_deref().unwrap_or("json") {
                "csv" => {
                    print!("{}", call("investigation.export_csv", json!({ "id": identifier })).await?["csv"].as_str().unwrap_or_default())
                }
                "json" => print(&call("investigation.export_json", json!({ "id": identifier })).await?),
                other => return Err(format!("unknown format '{other}'")),
            }
        }
        "providers" => {
            let listing = call("providers.list", json!({})).await?;
            if options.json {
                print(&listing);
            } else {
                for provider in listing["providers"].as_array().into_iter().flatten() {
                    println!(
                        "{:<16} {:<28} {:<8} {:>3}/min  {}",
                        provider["id"].as_str().unwrap_or_default(),
                        provider["name"].as_str().unwrap_or_default(),
                        if provider["enabled"] == true { "enabled" } else { "disabled" },
                        provider["rate_limit_per_minute"],
                        provider["supported_targets"]
                    );
                }
            }
        }
        "password-check" => {
            eprintln!("Enter the password on stdin (it is hashed locally; only a 5-character hash prefix is sent):");
            let mut line = Zeroizing::new(String::new());
            std::io::stdin().lock().read_line(&mut line).map_err(|error| error.to_string())?;
            let password = Zeroizing::new(line.trim_end_matches(['\r', '\n']).as_bytes().to_vec());
            let result = engine.check_password(password).await.map_err(|error| error.message)?;
            print(&serde_json::to_value(result).unwrap_or_default());
        }
        "hash-inventory" => {
            let source = positional(&rest).first().copied().ok_or("hash-inventory needs a file path or '-'")?;
            let mut text = Zeroizing::new(String::new());
            if source == "-" {
                std::io::stdin().read_to_string(&mut text).map_err(|error| error.to_string())?;
            } else {
                *text = std::fs::read_to_string(source).map_err(|error| error.to_string())?;
            }
            print(&serde_json::to_value(engine.hash_inventory(text).await.map_err(|error| error.message)?).unwrap_or_default());
        }
        "breach-catalog" => {
            if rest.iter().any(|argument| argument == "--refresh") {
                let refreshed = call("breach.catalog.refresh", json!({})).await?;
                eprintln!("Catalog refreshed: {} breaches (source: Have I Been Pwned, CC BY 4.0)", refreshed["breaches"]);
            }
            let query = positional(&rest).first().map(|value| value.to_string());
            print(&call("breach.catalog.search", json!({ "query": query, "limit": 25 })).await?);
        }
        "follow-ups" => {
            let identifier = positional(&rest).first().copied().ok_or("follow-ups needs an investigation id")?.to_string();
            let suggestions = call("investigation.suggestions", json!({ "id": identifier })).await?;
            if options.json {
                print(&suggestions);
            } else {
                for item in suggestions.as_array().into_iter().flatten() {
                    println!(
                        "{:<9} {:<40} {}{}",
                        item["target_type"].as_str().unwrap_or_default(),
                        item["value"].as_str().unwrap_or_default(),
                        item["reason"].as_str().unwrap_or_default(),
                        if item["already_investigated"] == true { " (already investigated)" } else { "" }
                    );
                }
            }
        }
        "sites" => {
            if positional(&rest).first() == Some(&"verify") {
                let results = call("sites.verify", json!({})).await?;
                let mut failed = 0;
                for result in results.as_array().into_iter().flatten() {
                    let passed = result["passed"] == true;
                    failed += usize::from(!passed);
                    println!(
                        "{} {:<16} known account: {:<12} random name: {}",
                        if passed { "ok  " } else { "FAIL" },
                        result["name"].as_str().unwrap_or_default(),
                        result["claimed"].as_str().unwrap_or_default(),
                        result["missing"].as_str().unwrap_or_default()
                    );
                }
                if failed > 0 {
                    return Err(format!("{failed} site definition(s) failed the self-test"));
                }
            } else {
                print(&call("sites.catalog", json!({})).await?);
            }
        }
        "bench" => {
            let runs: usize = flag(&rest, "--runs").and_then(|value| value.parse().ok()).unwrap_or(3);
            let mut purpose_arguments = rest.clone();
            if flag(&rest, "--purpose").is_none() {
                purpose_arguments.extend(["--purpose".to_string(), "Performance benchmark of public lookups".to_string()]);
            }
            let mut rows = Vec::new();
            for run in 1..=runs {
                let identifier = investigate(&engine, &purpose_arguments, Output::Silent).await?;
                let investigation = engine.storage().get_investigation(identifier).await.map_err(|error| error.message)?;
                let metrics = investigation.metrics.unwrap_or_default();
                rows.push(json!({
                    "run": run,
                    "status": investigation.status,
                    "startup_latency_ms": metrics.startup_latency_ms,
                    "time_to_first_finding_ms": metrics.time_to_first_finding_ms,
                    "total_duration_ms": metrics.total_duration_ms,
                    "http_requests": metrics.http_requests,
                    "cache_hit_rate": metrics.cache_hit_rate(),
                    "slowest_provider": metrics.provider_latencies.iter().max_by_key(|latency| latency.latency_ms).map(|latency| json!({"id": latency.provider_id, "ms": latency.latency_ms})),
                }));
                if investigation.status == InvestigationStatus::Failed {
                    break;
                }
            }
            print(
                &json!({ "runs": rows, "diagnostics": engine.call("engine.diagnostics", json!({})).await.map_err(|error| error.message)? }),
            );
        }
        "call" => {
            let method = rest.first().ok_or("call needs a method")?;
            let parameters: Value = match rest.get(1) {
                Some(raw) => serde_json::from_str(raw).map_err(|error| error.to_string())?,
                None => json!({}),
            };
            let value = engine.call(method, parameters).await.map_err(|error| format!("{:?}: {}", error.code, error.message))?;
            print(&value);
        }
        other => return Err(format!("unknown command '{other}'\n\n{USAGE}")),
    }
    let _ = std::io::stdout().flush();
    engine.shutdown().await;
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    let filter = tracing_subscriber::EnvFilter::try_from_env("SPECTRE_LOG").unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).try_init();
    let options = match parse_options() {
        Ok(options) => options,
        Err(message) => {
            if !message.is_empty() {
                eprintln!("{message}");
            }
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(options).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) if message.is_empty() => {
            eprint!("{USAGE}");
            ExitCode::from(2)
        }
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

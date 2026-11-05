//! Engine tests with in-process mock providers and mock HTTP services.
//! No test depends on live external APIs.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde_json::json;
use spectre_core::error::{ErrorCode, SpectreError, SpectreResult};
use spectre_core::model::*;
use spectre_core::provider::{FindingDraft, OsintProvider, ProviderCapability, ProviderContext};
use spectre_core::target::{InvestigationTarget, TargetType};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;

#[derive(Clone)]
enum Outcome {
    Profile { platform: &'static str, display_name: Option<&'static str>, links: Vec<&'static str> },
    Fail(ErrorCode),
    Hang,
}

struct MockProvider {
    id: &'static str,
    delay: Duration,
    outcome: Outcome,
    active: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}

impl MockProvider {
    fn new(id: &'static str, delay_ms: u64, outcome: Outcome) -> Self {
        Self { id, delay: Duration::from_millis(delay_ms), outcome, active: Arc::default(), peak: Arc::default() }
    }

    fn sharing(mut self, active: &Arc<AtomicUsize>, peak: &Arc<AtomicUsize>) -> Self {
        self.active = Arc::clone(active);
        self.peak = Arc::clone(peak);
        self
    }
}

#[async_trait]
impl OsintProvider for MockProvider {
    fn id(&self) -> &str {
        self.id
    }
    fn name(&self) -> &str {
        self.id
    }
    fn description(&self) -> &str {
        "mock"
    }
    fn homepage(&self) -> &str {
        "https://example.invalid"
    }
    fn supported_targets(&self) -> Vec<TargetType> {
        vec![TargetType::Username]
    }
    fn capabilities(&self) -> Vec<ProviderCapability> {
        vec![ProviderCapability::ProfileLookup]
    }
    fn allowed_hosts(&self) -> Vec<String> {
        Vec::new()
    }
    fn uses_network(&self) -> bool {
        false
    }

    async fn discover(&self, context: &ProviderContext, target: &InvestigationTarget) -> SpectreResult<Vec<FindingDraft>> {
        let now = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        let delay = if matches!(self.outcome, Outcome::Hang) { Duration::from_secs(60) } else { self.delay };
        let slept = spectre_core::http::sleep_cancellable(delay, &context.cancellation).await;
        self.active.fetch_sub(1, Ordering::SeqCst);
        slept?;
        match &self.outcome {
            Outcome::Fail(code) => Err(SpectreError::new(*code, format!("{} failed", self.id))),
            Outcome::Hang => Ok(Vec::new()),
            Outcome::Profile { platform, display_name, links } => {
                let username = target.value().to_string();
                let profile = ProfileFinding {
                    platform: platform.to_string(),
                    username: username.clone(),
                    profile_url: format!("https://{}.example.org/{username}", platform.to_ascii_lowercase()),
                    display_name: display_name.map(str::to_string),
                    linked_accounts: links.iter().map(|url| LinkedAccount { url: Some(url.to_string()), ..Default::default() }).collect(),
                    ..Default::default()
                };
                Ok(vec![FindingDraft {
                    title: format!("{platform} profile"),
                    summary: None,
                    confidence: Confidence::new(0.35, ConfidenceCategory::WeakEvidence, ["mock"]),
                    verification_status: VerificationStatus::PubliclyObserved,
                    sources: vec![context.source(Some(profile.profile_url.clone()), DiscoveryMethod::PublicApi)],
                    data: FindingData::Profile(profile),
                }])
            }
        }
    }
}

/// Publishes one finding immediately, then keeps working.
struct StreamingProvider;

#[async_trait]
impl OsintProvider for StreamingProvider {
    fn id(&self) -> &str {
        "streaming"
    }
    fn name(&self) -> &str {
        "streaming"
    }
    fn description(&self) -> &str {
        "mock"
    }
    fn homepage(&self) -> &str {
        "https://example.invalid"
    }
    fn supported_targets(&self) -> Vec<TargetType> {
        vec![TargetType::Username]
    }
    fn capabilities(&self) -> Vec<ProviderCapability> {
        vec![ProviderCapability::ProfileLookup]
    }
    fn allowed_hosts(&self) -> Vec<String> {
        Vec::new()
    }
    fn deadline(&self, _configured: Duration) -> Duration {
        Duration::from_secs(5)
    }

    async fn discover(&self, context: &ProviderContext, target: &InvestigationTarget) -> SpectreResult<Vec<FindingDraft>> {
        let draft = |platform: &str| FindingDraft {
            title: format!("{platform} profile"),
            summary: None,
            confidence: Confidence::new(0.35, ConfidenceCategory::WeakEvidence, ["mock"]),
            verification_status: VerificationStatus::PubliclyObserved,
            sources: vec![context.source(None, DiscoveryMethod::PublicApi)],
            data: FindingData::Profile(ProfileFinding {
                platform: platform.into(),
                username: target.value().into(),
                profile_url: format!("https://{}.example.org/{}", platform.to_ascii_lowercase(), target.value()),
                ..Default::default()
            }),
        };
        assert!(context.publish(draft("Early")).is_none(), "the engine provides a sink");
        tokio::time::sleep(Duration::from_millis(300)).await;
        Ok(vec![draft("Late")])
    }
}

async fn engine_with(providers: Vec<Arc<dyn OsintProvider>>, configure: impl FnOnce(&mut EngineConfig)) -> Arc<Engine> {
    let mut config = EngineConfig { providers: Some(providers), allow_loopback_for_tests: true, ..Default::default() };
    configure(&mut config);
    Engine::open(config).await.unwrap()
}

fn request(value: &str) -> StartInvestigationRequest {
    StartInvestigationRequest {
        target_type: TargetType::Username,
        value: value.into(),
        purpose: "Authorized assessment of my own accounts".into(),
        provider_ids: None,
        default_region: None,
    }
}

/// Drain events until the investigation finishes.
fn collect_events(engine: &Engine, investigation_id: Uuid) -> Vec<InvestigationEvent> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut events = Vec::new();
    loop {
        let batch = engine.events().wait(investigation_id, 64, Duration::from_millis(200));
        events.extend(batch.events);
        if batch.finished || Instant::now() > deadline {
            return events;
        }
    }
}

async fn wait_for(engine: &Arc<Engine>, investigation_id: Uuid) -> Vec<InvestigationEvent> {
    let engine = Arc::clone(engine);
    tokio::task::spawn_blocking(move || collect_events(&engine, investigation_id)).await.unwrap()
}

fn finished_status(events: &[InvestigationEvent]) -> Option<InvestigationStatus> {
    events.iter().find_map(|event| match &event.event {
        InvestigationEventKind::Finished { status, .. } => Some(*status),
        _ => None,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn findings_stream_before_slow_providers_finish() {
    let engine = engine_with(
        vec![
            Arc::new(MockProvider::new(
                "fast",
                10,
                Outcome::Profile { platform: "Alpha", display_name: Some("Jane Doe"), links: vec!["https://beta.example.org/jane"] },
            )),
            Arc::new(MockProvider::new(
                "slow",
                400,
                Outcome::Profile { platform: "Beta", display_name: Some("Jane Doe"), links: vec!["https://alpha.example.org/jane"] },
            )),
        ],
        |_| {},
    )
    .await;
    let investigation = engine.start_investigation(request("jane")).await.unwrap();
    let events = wait_for(&engine, investigation.id).await;

    let first_finding = events.iter().position(|event| matches!(event.event, InvestigationEventKind::FindingDiscovered { .. })).unwrap();
    let slow_done = events
        .iter()
        .position(|event| matches!(&event.event, InvestigationEventKind::ProviderCompleted { provider_id, .. } if provider_id == "slow"))
        .unwrap();
    assert!(first_finding < slow_done, "fast findings must stream before the slow provider completes");
    assert!(events.windows(2).all(|pair| pair[0].sequence < pair[1].sequence));
    assert_eq!(finished_status(&events), Some(InvestigationStatus::Completed));

    let detail = engine.storage().detail(investigation.id).await.unwrap();
    assert_eq!(detail.investigation.status, InvestigationStatus::Completed);
    assert_eq!(detail.findings.len(), 2);
    let metrics = detail.investigation.metrics.unwrap();
    assert!(metrics.time_to_first_finding_ms.unwrap() < metrics.total_duration_ms);
    assert_eq!(metrics.provider_latencies.len(), 2);

    // Mutually linked profiles with the same display name are strong evidence.
    let root = detail.graph.nodes.iter().find(|node| node.is_target).unwrap().id;
    let target_edges: Vec<_> = detail.graph.edges.iter().filter(|edge| edge.source_identity == root).collect();
    assert_eq!(target_edges.len(), 2);
    assert!(target_edges.iter().all(|edge| edge.category == ConfidenceCategory::StrongEvidence), "{target_edges:?}");
    assert!(detail.findings.iter().all(|finding| finding.confidence.category == ConfidenceCategory::StrongEvidence));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn global_concurrency_limit_is_enforced() {
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let names = ["p1", "p2", "p3", "p4", "p5", "p6"];
    let providers: Vec<Arc<dyn OsintProvider>> = names
        .iter()
        .map(|name| {
            Arc::new(
                MockProvider::new(name, 60, Outcome::Profile { platform: "X", display_name: None, links: vec![] }).sharing(&active, &peak),
            ) as Arc<dyn OsintProvider>
        })
        .collect();
    let engine = engine_with(providers, |_| {}).await;
    engine.update_settings(EngineSettings { max_concurrency: 2, ..Default::default() }).await.unwrap();
    let first = engine.start_investigation(request("alice")).await.unwrap();
    let second = engine.start_investigation(request("bob")).await.unwrap();
    wait_for(&engine, first.id).await;
    wait_for(&engine, second.id).await;
    assert!(peak.load(Ordering::SeqCst) <= 2, "peak concurrency {} exceeded limit", peak.load(Ordering::SeqCst));
    assert!(peak.load(Ordering::SeqCst) >= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancellation_stops_hanging_providers_promptly() {
    let engine = engine_with(
        vec![
            Arc::new(MockProvider::new("quick", 5, Outcome::Profile { platform: "Alpha", display_name: None, links: vec![] })),
            Arc::new(MockProvider::new("stuck", 0, Outcome::Hang)),
        ],
        |_| {},
    )
    .await;
    let investigation = engine.start_investigation(request("carol")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    let started = Instant::now();
    assert!(engine.cancel_investigation(investigation.id));
    let events = wait_for(&engine, investigation.id).await;
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(finished_status(&events), Some(InvestigationStatus::Cancelled));
    let detail = engine.storage().detail(investigation.id).await.unwrap();
    assert_eq!(detail.investigation.status, InvestigationStatus::Cancelled);
    assert_eq!(detail.findings.len(), 1, "findings gathered before cancellation are kept");
    assert!(!engine.is_running(investigation.id));
    assert!(!engine.cancel_investigation(investigation.id));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn provider_failures_are_recorded_not_swallowed() {
    let engine = engine_with(
        vec![
            Arc::new(MockProvider::new("works", 5, Outcome::Profile { platform: "Alpha", display_name: None, links: vec![] })),
            Arc::new(MockProvider::new("limited", 5, Outcome::Fail(ErrorCode::RateLimited))),
        ],
        |_| {},
    )
    .await;
    let partial = engine.start_investigation(request("dave")).await.unwrap();
    let events = wait_for(&engine, partial.id).await;
    assert_eq!(finished_status(&events), Some(InvestigationStatus::PartiallyCompleted));
    assert!(
        events.iter().any(
            |event| matches!(&event.event, InvestigationEventKind::ProviderFailed { failure } if failure.code == ErrorCode::RateLimited)
        )
    );
    let stored = engine.storage().get_investigation(partial.id).await.unwrap();
    assert_eq!(stored.errors.len(), 1);

    let mut only_failing = request("erin");
    only_failing.provider_ids = Some(vec!["limited".into()]);
    let failed = engine.start_investigation(only_failing).await.unwrap();
    assert_eq!(finished_status(&wait_for(&engine, failed.id).await), Some(InvestigationStatus::Failed));
}

#[tokio::test]
async fn start_requires_authorization_record_and_known_providers() {
    let engine = engine_with(vec![Arc::new(MockProvider::new("works", 1, Outcome::Hang))], |_| {}).await;
    let mut short = request("frank");
    short.purpose = "  test ".into();
    assert_eq!(engine.start_investigation(short).await.unwrap_err().code, ErrorCode::AuthorizationRequired);
    let mut unknown = request("frank");
    unknown.provider_ids = Some(vec!["nope".into()]);
    assert_eq!(engine.start_investigation(unknown).await.unwrap_err().code, ErrorCode::InvalidInput);
    let mut invalid = request("../etc");
    invalid.value = "../etc".into();
    assert_eq!(engine.start_investigation(invalid).await.unwrap_err().code, ErrorCode::InvalidInput);
    let email = StartInvestigationRequest { target_type: TargetType::Email, value: "a@example.org".into(), ..request("x") };
    assert_eq!(engine.start_investigation(email).await.unwrap_err().code, ErrorCode::InvalidInput, "no provider supports email here");
}

const MULTIPLE: &str = include_str!("../../../../tests/fixtures/hibp/breachedaccount_multiple.json");

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn breach_lookups_require_verified_ownership() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/breachedaccount/owner@example.org"))
        .respond_with(ResponseTemplate::new(200).set_body_string(MULTIPLE))
        .mount(&server)
        .await;
    let base = url::Url::parse(&format!("{}/api/v3/", server.uri())).unwrap();
    let engine = engine_with(vec![Arc::new(MockProvider::new("works", 1, Outcome::Hang))], |config| config.hibp_base = Some(base)).await;

    let denied = engine.lookup_breaches("owner@example.org", None).await.unwrap_err();
    assert_eq!(denied.code, ErrorCode::AuthorizationRequired);
    assert_eq!(server.received_requests().await.unwrap().len(), 0, "nothing is sent for unverified addresses");

    engine.attest_email("owner@example.org", "This is my personal mailbox").await.unwrap();
    let missing_key = engine.lookup_breaches("owner@example.org", None).await.unwrap_err();
    assert_eq!(missing_key.code, ErrorCode::CredentialsMissing);

    engine.credentials().set(spectre_core::credentials::ids::HIBP_API_KEY, Zeroizing::new("k".into()));
    let report = engine.lookup_breaches("Owner@Example.org", None).await.unwrap();
    assert_eq!(report.breaches.len(), 3);
    assert!(report.verified);
    assert_eq!(report.verification_method, Some(VerificationMethod::InvestigatorAttestation));
    assert!(report.risk.level >= RiskLevel::Medium);
    assert_eq!(engine.stored_exposures("owner@example.org").await.unwrap().breaches.len(), 3);

    let audit = engine.storage().audit_events(20).await.unwrap();
    assert!(audit.iter().any(|event| event.event_type == "breach_lookup"));
    assert!(audit.iter().any(|event| event.event_type == "email_ownership_attested"));
    assert!(!serde_json::to_string(&audit).unwrap().contains("\"k\""), "API keys never reach the audit log");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn password_check_sends_prefix_only() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/range/5BAA6"))
        .respond_with(ResponseTemplate::new(200).set_body_string("1E4C9B93F3F0682250B6CF8331B7EE68FD8:7\r\n"))
        .mount(&server)
        .await;
    let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
    let engine =
        engine_with(vec![Arc::new(MockProvider::new("works", 1, Outcome::Hang))], |config| config.pwned_passwords_base = Some(base)).await;
    let result = engine.check_password(Zeroizing::new(b"password".to_vec())).await.unwrap();
    assert!(result.compromised);
    assert_eq!(result.occurrences, 7);
    let audit = serde_json::to_string(&engine.storage().audit_events(10).await.unwrap()).unwrap();
    assert!(!audit.contains("5BAA6") && !audit.contains("password\""), "audit holds no password material");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn json_api_end_to_end() {
    let engine = engine_with(
        vec![
            Arc::new(MockProvider::new("alpha", 5, Outcome::Profile { platform: "Alpha", display_name: None, links: vec![] })),
            Arc::new(MockProvider::new("beta", 5, Outcome::Profile { platform: "Beta", display_name: None, links: vec![] })),
        ],
        |_| {},
    )
    .await;
    let validation = engine.call("target.validate", json!({"target_type": "phone", "value": "+1 650 253 0000"})).await.unwrap();
    assert_eq!(validation["valid"], true);
    assert_eq!(validation["normalized"], "+16502530000");
    assert_eq!(validation["phone"]["region_code"], "US");
    let invalid = engine.call("target.validate", json!({"target_type": "domain", "value": "localhost"})).await.unwrap();
    assert_eq!(invalid["valid"], false);

    let started = engine
        .call("investigation.start", json!({"target_type": "username", "value": "grace", "purpose": "Authorized red-team engagement #42"}))
        .await
        .unwrap();
    let identifier = started["id"].as_str().unwrap().to_string();
    let mut finished = false;
    for _ in 0..100 {
        let batch = engine.call("investigation.events", json!({"id": identifier, "timeout_ms": 200})).await.unwrap();
        if batch["finished"] == true {
            finished = true;
            break;
        }
    }
    assert!(finished);
    let detail = engine.call("investigation.get", json!({"id": identifier})).await.unwrap();
    assert_eq!(detail["investigation"]["status"], "completed");
    assert_eq!(detail["findings"].as_array().unwrap().len(), 2);
    assert_eq!(detail["findings"][0]["data"]["kind"], "profile");

    let edge = detail["graph"]["edges"][0]["id"].as_str().unwrap().to_string();
    let graph = engine.call("relationship.decide", json!({"relationship_id": edge, "decision": "confirmed"})).await.unwrap();
    let decided = graph["edges"].as_array().unwrap().iter().find(|candidate| candidate["id"] == edge.as_str()).unwrap();
    assert_eq!(decided["category"], "confirmed");
    assert_eq!(decided["investigator_decision"], "confirmed");

    let csv = engine.call("investigation.export_csv", json!({"id": identifier})).await.unwrap();
    assert_eq!(csv["csv"].as_str().unwrap().lines().count(), 3);
    let bundle = engine.call("investigation.export_json", json!({"id": identifier})).await.unwrap();
    assert_eq!(bundle["format"], "spectre.investigation");

    let settings = engine.call("settings.update", json!({"max_concurrency": 6, "cache_ttl_secs": 60})).await.unwrap();
    assert_eq!(settings["max_concurrency"], 6);
    assert_eq!(engine.call("settings.get", json!({})).await.unwrap()["cache_ttl_secs"], 60);
    let providers =
        engine.call("providers.update", json!({"provider_id": "beta", "enabled": false, "rate_limit_per_minute": 5})).await.unwrap();
    assert_eq!(providers["enabled"], false);
    let listing = engine.call("providers.list", json!({})).await.unwrap();
    assert_eq!(listing["providers"].as_array().unwrap().len(), 2);
    assert_eq!(listing["services"].as_array().unwrap().len(), 2);

    let credentials = engine.call("credentials.set", json!({"credential_id": "hibp", "secret": "abc"})).await.unwrap();
    assert_eq!(credentials["configured"], json!(["hibp"]));
    assert!(!serde_json::to_string(&engine.call("engine.diagnostics", json!({})).await.unwrap()).unwrap().contains("abc"));

    let unknown = engine.call("does.not.exist", json!({})).await.unwrap_err();
    assert_eq!(unknown.code, ErrorCode::InvalidInput);
    let bad = engine.call("investigation.get", json!({"id": "not-a-uuid"})).await.unwrap_err();
    assert_eq!(bad.code, ErrorCode::InvalidInput);

    engine.call("investigation.delete", json!({"id": identifier})).await.unwrap();
    assert_eq!(engine.call("investigation.get", json!({"id": identifier})).await.unwrap_err().code, ErrorCode::NotFound);
    let stats = engine.call("dashboard.stats", json!({})).await.unwrap();
    assert_eq!(stats["investigations"], 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backup_and_restore_round_trip() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("spectre.sqlite");
    let engine = engine_with(
        vec![Arc::new(MockProvider::new("alpha", 1, Outcome::Profile { platform: "Alpha", display_name: None, links: vec![] }))],
        |config| {
            config.database_path = Some(database.clone());
        },
    )
    .await;
    let investigation = engine.start_investigation(request("heidi")).await.unwrap();
    wait_for(&engine, investigation.id).await;
    let backup = directory.path().join("backup.sqlite");
    engine.backup(backup.to_str().unwrap()).await.unwrap();
    engine.delete_investigation(investigation.id).await.unwrap();
    assert!(engine.storage().get_investigation(investigation.id).await.is_err());
    engine.restore(backup.to_str().unwrap()).await.unwrap();
    assert_eq!(engine.storage().get_investigation(investigation.id).await.unwrap().findings_count, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn providers_can_stream_findings_before_returning() {
    let engine = engine_with(vec![Arc::new(StreamingProvider)], |_| {}).await;
    let investigation = engine.start_investigation(request("ivy")).await.unwrap();
    let events = wait_for(&engine, investigation.id).await;
    let position = |predicate: &dyn Fn(&InvestigationEventKind) -> bool| events.iter().position(|event| predicate(&event.event)).unwrap();
    let early = position(&|kind| matches!(kind, InvestigationEventKind::FindingDiscovered { finding } if finding.title == "Early profile"));
    let completed = position(&|kind| matches!(kind, InvestigationEventKind::ProviderCompleted { .. }));
    assert!(early < completed);
    assert!(events.iter().any(|event| matches!(&event.event, InvestigationEventKind::ProviderCompleted { findings: 2, .. })));
    assert_eq!(engine.storage().findings_for(investigation.id).await.unwrap().len(), 2);

    let follow_ups = engine.call("investigation.suggestions", json!({ "id": investigation.id })).await.unwrap();
    assert!(follow_ups.as_array().unwrap().is_empty());
    let catalog = engine.call("sites.catalog", json!({})).await.unwrap();
    assert!(catalog["sites"].as_array().unwrap().len() >= 30);
}

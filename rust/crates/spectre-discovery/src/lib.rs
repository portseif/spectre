//! The Spectre investigation engine.
//!
//! [`Engine`] ties providers, correlation, breach intelligence, auditing, and
//! storage together. It is runtime-agnostic (any Tokio runtime) and exposes:
//!
//! * typed async methods for embedding in Rust, and
//! * [`Engine::call`], a JSON method dispatcher shared by the C FFI and CLI.

mod api;
pub mod events;
mod export;
mod run;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use spectre_audit::{HashInventory, PasswordCheckResult, PwnedPasswordsClient};
use spectre_breach::{AuthorizedAccount, BreachProvider, HIBP_ATTRIBUTION, HibpClient, assess_risk};
use spectre_core::config::{EngineSettings, ProviderConfig};
use spectre_core::credentials::CredentialStore;
use spectre_core::error::{ErrorCode, SpectreError, SpectreResult};
use spectre_core::http::{EndpointPolicy, HttpClient, HttpSettings, RequestStats};
use spectre_core::model::*;
use spectre_core::provider::{OsintProvider, ProviderContext, ProviderDescriptor};
use spectre_core::target::{InvestigationTarget, TargetType, normalize_email};
use spectre_correlation::CorrelationContext;
use spectre_providers::dns::DohResolver;
use spectre_storage::Storage;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

pub use events::{EventBatch, EventHub};
pub use export::findings_csv;
pub use spectre_storage::{AuditEvent, DashboardStats, InvestigationBundle, StorageInfo};

pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");
const MIN_PURPOSE_CHARS: usize = 10;

/// How to construct an engine.
#[derive(Default)]
pub struct EngineConfig {
    /// SQLite file. `None` uses an in-memory database.
    pub database_path: Option<PathBuf>,
    /// Replace the built-in providers (tests, custom builds).
    pub providers: Option<Vec<Arc<dyn OsintProvider>>>,
    pub hibp_base: Option<Url>,
    pub pwned_passwords_base: Option<Url>,
    pub doh_endpoint: Option<Url>,
    /// Permit plain-HTTP loopback endpoints (mock servers in tests only).
    pub allow_loopback_for_tests: bool,
}

/// JSON-friendly configuration accepted by the FFI.
#[derive(Debug, Default, Deserialize)]
pub struct EngineOptions {
    pub database_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartInvestigationRequest {
    pub target_type: TargetType,
    pub value: String,
    pub purpose: String,
    #[serde(default)]
    pub provider_ids: Option<Vec<String>>,
    #[serde(default)]
    pub default_region: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderStatus {
    #[serde(flatten)]
    pub descriptor: ProviderDescriptor,
    pub enabled: bool,
    pub rate_limit_per_minute: u32,
    pub credential_configured: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub id: String,
    pub name: String,
    pub description: String,
    pub credential_id: Option<String>,
    pub credential_required: bool,
    pub credential_configured: bool,
    pub hosts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostics {
    pub engine_version: String,
    pub storage: StorageInfo,
    pub providers: usize,
    pub active_investigations: usize,
    pub http_requests: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_entries: usize,
    pub retries: u64,
    pub allowed_hosts: Vec<String>,
    pub credentials_configured: Vec<String>,
    pub uptime_seconds: u64,
}

struct ActiveInvestigation {
    cancellation: CancellationToken,
}

pub struct Engine {
    storage: RwLock<Arc<Storage>>,
    http: HttpClient,
    providers: Vec<Arc<dyn OsintProvider>>,
    hibp: Arc<HibpClient>,
    pwned_passwords: PwnedPasswordsClient,
    credentials: Arc<CredentialStore>,
    settings: RwLock<EngineSettings>,
    provider_configs: RwLock<HashMap<String, ProviderConfig>>,
    concurrency: RwLock<Arc<Semaphore>>,
    active: Mutex<HashMap<Uuid, ActiveInvestigation>>,
    events: EventHub,
    started_at: Instant,
}

impl Engine {
    pub async fn open(config: EngineConfig) -> SpectreResult<Arc<Self>> {
        let storage = match &config.database_path {
            Some(path) => Storage::open(path).await?,
            None => Storage::open_in_memory().await?,
        };
        let settings = storage.settings().await?;
        let providers = config.providers.unwrap_or_else(|| {
            let mut providers = spectre_providers::default_providers();
            providers.push(Arc::new(spectre_breach::HibpCatalogProvider::default()));
            providers
        });
        let hibp = Arc::new(config.hibp_base.map(HibpClient::with_base).unwrap_or_default());
        let pwned_passwords = config.pwned_passwords_base.map(PwnedPasswordsClient::with_base).unwrap_or_default();
        let resolver = config.doh_endpoint.map(DohResolver::with_endpoint).unwrap_or_default();

        let policy = if config.allow_loopback_for_tests { EndpointPolicy::for_testing() } else { EndpointPolicy::default() };
        for provider in &providers {
            for host in provider.allowed_hosts() {
                policy.allow_host(host);
            }
        }
        for host in hibp.allowed_hosts().into_iter().chain([pwned_passwords.host(), resolver.host()]) {
            policy.allow_host(host);
        }
        let http = HttpClient::new(Arc::new(policy), HttpSettings::from(&settings))?;

        let provider_configs: HashMap<String, ProviderConfig> =
            storage.provider_configs().await?.into_iter().map(|config| (config.provider_id.clone(), config)).collect();
        for provider in &providers {
            let limit = provider_configs
                .get(provider.id())
                .and_then(|config| config.rate_limit_per_minute)
                .unwrap_or_else(|| provider.default_rate_limit_per_minute());
            http.set_rate_limit(provider.id(), Some(limit));
        }

        // Decode libphonenumber metadata off the request path (~0.3 s cold).
        tokio::task::spawn_blocking(|| {
            let _ = spectre_core::target::normalize_phone("+16502530000", None);
        });

        let interrupted = storage.fail_interrupted().await?;
        if interrupted > 0 {
            tracing::warn!(interrupted, "marked investigations interrupted by a previous shutdown as failed");
        }
        if settings.retention_days > 0 {
            let cutoff = Utc::now() - chrono::Duration::days(i64::from(settings.retention_days));
            let purged = storage.purge_before(cutoff).await?;
            if purged > 0 {
                storage
                    .record_audit(
                        None,
                        "retention_purge",
                        serde_json::json!({ "purged": purged, "retention_days": settings.retention_days }),
                    )
                    .await?;
            }
        }

        Ok(Arc::new(Self {
            storage: RwLock::new(Arc::new(storage)),
            http,
            providers,
            hibp,
            pwned_passwords,
            credentials: Arc::new(CredentialStore::new()),
            concurrency: RwLock::new(Arc::new(Semaphore::new(settings.max_concurrency as usize))),
            settings: RwLock::new(settings),
            provider_configs: RwLock::new(provider_configs),
            active: Mutex::new(HashMap::new()),
            events: EventHub::default(),
            started_at: Instant::now(),
        }))
    }

    pub fn storage(&self) -> Arc<Storage> {
        Arc::clone(&self.storage.read().unwrap_or_else(|poisoned| poisoned.into_inner()))
    }

    pub fn events(&self) -> &EventHub {
        &self.events
    }

    pub fn credentials(&self) -> &CredentialStore {
        &self.credentials
    }

    pub fn settings(&self) -> EngineSettings {
        self.settings.read().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
    }

    fn semaphore(&self) -> Arc<Semaphore> {
        Arc::clone(&self.concurrency.read().unwrap_or_else(|poisoned| poisoned.into_inner()))
    }

    fn context(
        &self,
        provider_id: &str,
        provider_name: &str,
        cancellation: CancellationToken,
        stats: Arc<RequestStats>,
    ) -> ProviderContext {
        ProviderContext {
            provider_id: provider_id.to_string(),
            provider_name: provider_name.to_string(),
            http: self.http.clone(),
            credentials: Arc::clone(&self.credentials),
            cancellation,
            stats,
            sink: None,
        }
    }

    fn is_enabled(&self, provider_id: &str) -> bool {
        self.provider_configs.read().unwrap_or_else(|poisoned| poisoned.into_inner()).get(provider_id).is_none_or(|config| config.enabled)
    }

    fn active_ids(&self) -> Vec<Uuid> {
        self.active.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).keys().copied().collect()
    }

    // -----------------------------------------------------------------------
    // Investigations
    // -----------------------------------------------------------------------

    /// Validate the request, persist the investigation, and start it in the
    /// background. Findings stream through [`Engine::events`].
    pub async fn start_investigation(self: &Arc<Self>, request: StartInvestigationRequest) -> SpectreResult<Investigation> {
        let requested_at = Instant::now();
        let target = InvestigationTarget::parse_with_region(request.target_type, &request.value, request.default_region.as_deref())?;
        let purpose = request.purpose.trim().to_string();
        if purpose.chars().count() < MIN_PURPOSE_CHARS {
            return Err(SpectreError::authorization_required(format!(
                "Record the authorization basis and scope for this investigation (at least {MIN_PURPOSE_CHARS} characters)."
            )));
        }
        if purpose.chars().count() > 2000 {
            return Err(SpectreError::invalid_input("purpose must be at most 2000 characters"));
        }
        let candidates: Vec<Arc<dyn OsintProvider>> =
            self.providers.iter().filter(|provider| provider.supports(target.target_type())).cloned().collect();
        let selected: Vec<Arc<dyn OsintProvider>> = match &request.provider_ids {
            Some(requested) => {
                let known: HashSet<&str> = candidates.iter().map(|provider| provider.id()).collect();
                if let Some(unknown) = requested.iter().find(|id| !known.contains(id.as_str())) {
                    return Err(SpectreError::invalid_input(format!(
                        "provider '{unknown}' does not exist or does not support {} targets",
                        target.target_type()
                    )));
                }
                candidates.into_iter().filter(|provider| requested.iter().any(|id| id == provider.id())).collect()
            }
            None => candidates.into_iter().filter(|provider| self.is_enabled(provider.id())).collect(),
        };
        if selected.is_empty() {
            return Err(SpectreError::invalid_input(format!("no enabled providers support {} targets", target.target_type())));
        }

        let investigation = Investigation {
            id: Uuid::new_v4(),
            target_type: target.target_type(),
            target,
            purpose: purpose.clone(),
            status: InvestigationStatus::Pending,
            progress: 0.0,
            providers: selected.iter().map(|provider| provider.id().to_string()).collect(),
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            findings_count: 0,
            errors: Vec::new(),
            metrics: None,
        };
        let storage = self.storage();
        storage.create_investigation(&investigation).await?;
        storage
            .record_audit(
                Some(investigation.id),
                "investigation_started",
                serde_json::json!({ "target_type": investigation.target_type, "providers": investigation.providers, "purpose": purpose }),
            )
            .await?;

        let cancellation = CancellationToken::new();
        self.active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(investigation.id, ActiveInvestigation { cancellation: cancellation.clone() });
        self.events.open(investigation.id);
        let engine = Arc::clone(self);
        let running = investigation.clone();
        tokio::spawn(async move {
            engine.run_investigation(running, selected, cancellation, requested_at).await;
        });
        Ok(investigation)
    }

    pub fn cancel_investigation(&self, investigation_id: Uuid) -> bool {
        match self.active.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).get(&investigation_id) {
            Some(active) => {
                active.cancellation.cancel();
                true
            }
            None => false,
        }
    }

    pub fn is_running(&self, investigation_id: Uuid) -> bool {
        self.active.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).contains_key(&investigation_id)
    }

    pub async fn delete_investigation(&self, investigation_id: Uuid) -> SpectreResult<()> {
        if self.is_running(investigation_id) {
            return Err(SpectreError::invalid_input("cancel the investigation before deleting it"));
        }
        let storage = self.storage();
        storage.delete_investigation(investigation_id).await?;
        self.events.discard(investigation_id);
        storage.record_audit(Some(investigation_id), "investigation_deleted", serde_json::json!({})).await
    }

    /// Recompute the identity graph and profile confidence for an investigation.
    pub async fn correlate(&self, investigation_id: Uuid) -> SpectreResult<IdentityGraph> {
        let storage = self.storage();
        let investigation = storage.get_investigation(investigation_id).await?;
        let findings = storage.findings_for(investigation_id).await?;
        let context = CorrelationContext {
            decisions: storage.decisions_for(investigation_id).await?,
            verified_emails: storage.verified_emails().await?.into_iter().collect(),
        };
        let result = spectre_correlation::correlate(investigation_id, &investigation.target, &findings, &context);
        storage.replace_graph(investigation_id, &result.graph).await?;
        storage.update_finding_confidence(&result.finding_confidence).await?;
        Ok(result.graph)
    }

    /// Identifiers the findings point to, flagged when already investigated.
    pub async fn follow_ups(&self, investigation_id: Uuid) -> SpectreResult<Vec<spectre_correlation::FollowUp>> {
        let storage = self.storage();
        let investigation = storage.get_investigation(investigation_id).await?;
        let findings = storage.findings_for(investigation_id).await?;
        let existing: HashSet<(TargetType, String)> = storage
            .list_investigations(500, 0, None)
            .await?
            .into_iter()
            .map(|item| (item.target_type, item.target.value().to_ascii_lowercase()))
            .collect();
        let mut suggestions = spectre_correlation::suggest_follow_ups(&investigation.target, &findings);
        for suggestion in &mut suggestions {
            suggestion.already_investigated = existing.contains(&(suggestion.target_type, suggestion.value.to_ascii_lowercase()));
        }
        Ok(suggestions)
    }

    /// Live self-test of the profile-page catalog (makes network requests).
    pub async fn verify_site_catalog(&self) -> Vec<spectre_providers::username::sites::SiteVerification> {
        let provider = spectre_providers::username::sites::SiteCheckProvider::default();
        let context = self.context(provider.id(), provider.name(), CancellationToken::new(), Arc::new(RequestStats::default()));
        spectre_providers::username::sites::verify_catalog(&context, &provider).await
    }

    pub async fn decide_relationship(&self, relationship_id: Uuid, decision: Option<InvestigatorDecision>) -> SpectreResult<IdentityGraph> {
        let storage = self.storage();
        let investigation_id = storage.set_relationship_decision(relationship_id, decision).await?;
        storage
            .record_audit(
                Some(investigation_id),
                "relationship_decision",
                serde_json::json!({ "relationship_id": relationship_id, "decision": decision.map(InvestigatorDecision::as_str) }),
            )
            .await?;
        self.correlate(investigation_id).await
    }

    async fn recorrelate_matching(&self, predicate: impl Fn(&Investigation) -> bool) -> SpectreResult<()> {
        let storage = self.storage();
        for investigation in storage.list_investigations(500, 0, None).await? {
            if predicate(&investigation) && investigation.status.is_terminal() {
                self.correlate(investigation.id).await?;
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Ownership verification
    // -----------------------------------------------------------------------

    pub async fn attest_email(&self, email: &str, statement: &str) -> SpectreResult<EmailRecord> {
        let email = normalize_email(email)?;
        let statement = statement.trim();
        if statement.chars().count() < MIN_PURPOSE_CHARS {
            return Err(SpectreError::authorization_required(
                "Describe the ownership or written authorization for this address (at least 10 characters).",
            ));
        }
        let storage = self.storage();
        let record = storage
            .set_email_verification(
                &email,
                VerificationStatus::OwnershipVerified,
                Some(VerificationMethod::InvestigatorAttestation),
                Some(statement),
            )
            .await?;
        storage.record_audit(None, "email_ownership_attested", serde_json::json!({ "email": email, "statement": statement })).await?;
        self.recorrelate_matching(|investigation| investigation.target.value() == email).await?;
        Ok(record)
    }

    pub async fn revoke_email(&self, email: &str) -> SpectreResult<EmailRecord> {
        let email = normalize_email(email)?;
        let storage = self.storage();
        let record = storage.set_email_verification(&email, VerificationStatus::Unverified, None, None).await?;
        storage.record_audit(None, "email_ownership_revoked", serde_json::json!({ "email": email })).await?;
        self.recorrelate_matching(|investigation| investigation.target.value() == email).await?;
        Ok(record)
    }

    // -----------------------------------------------------------------------
    // Breach intelligence
    // -----------------------------------------------------------------------

    /// Account-specific breach lookup. Requires verified ownership.
    pub async fn lookup_breaches(&self, email: &str, investigation_id: Option<Uuid>) -> SpectreResult<BreachExposureReport> {
        let email = normalize_email(email)?;
        let storage = self.storage();
        let record = storage.ensure_email(&email).await?;
        let account = AuthorizedAccount::from_record(&record)?;
        if let Some(investigation_id) = investigation_id {
            storage.get_investigation(investigation_id).await?;
            if self.is_running(investigation_id) {
                return Err(SpectreError::invalid_input("wait for the investigation to finish before adding breach results"));
            }
        }
        let context = self.context(self.hibp.id(), self.hibp.name(), CancellationToken::new(), Arc::new(RequestStats::default()));
        let breaches = self.hibp.account_breaches(&context, &account).await?;
        storage.upsert_incidents(&breaches).await?;
        storage.record_exposures(&email, &breaches.iter().map(|breach| breach.name.clone()).collect::<Vec<_>>()).await?;
        storage
            .record_audit(
                investigation_id,
                "breach_lookup",
                serde_json::json!({ "email": email, "method": account.method(), "breaches": breaches.len() }),
            )
            .await?;

        if let Some(investigation_id) = investigation_id {
            for incident in &breaches {
                let finding = Finding {
                    id: Uuid::new_v4(),
                    investigation_id,
                    provider_id: "hibp-account".into(),
                    title: format!("{email} in the {} breach", incident.title),
                    summary: Some(incident.data_classes.join(", ")),
                    confidence: Confidence::new(
                        1.0,
                        ConfidenceCategory::Confirmed,
                        ["Reported by Have I Been Pwned for an ownership-verified address"],
                    ),
                    verification_status: VerificationStatus::OwnershipVerified,
                    discovered_at: Utc::now(),
                    sources: vec![
                        context.source(Some(format!("https://haveibeenpwned.com/Breach/{}", incident.name)), DiscoveryMethod::BreachApi),
                    ],
                    data: FindingData::BreachIncident(BreachFinding { exposed_account: Some(email.clone()), incident: incident.clone() }),
                };
                storage.insert_finding(&finding).await?;
            }
            self.correlate(investigation_id).await?;
        }
        Ok(BreachExposureReport {
            email,
            verified: true,
            verification_method: Some(account.method()),
            checked_at: Utc::now(),
            risk: assess_risk(&breaches),
            breaches,
            source_attribution: HIBP_ATTRIBUTION.into(),
        })
    }

    /// Previously recorded exposures (no network access).
    pub async fn stored_exposures(&self, email: &str) -> SpectreResult<BreachExposureReport> {
        let email = normalize_email(email)?;
        let storage = self.storage();
        let record = storage.email_record(&email).await?;
        let breaches = storage.exposures_for(&email).await?;
        Ok(BreachExposureReport {
            verified: record.verification_status == VerificationStatus::OwnershipVerified,
            verification_method: record.verification_method,
            checked_at: record.last_breach_check_at.unwrap_or(record.created_at),
            risk: assess_risk(&breaches),
            breaches,
            email,
            source_attribution: HIBP_ATTRIBUTION.into(),
        })
    }

    pub async fn refresh_breach_catalog(&self) -> SpectreResult<u64> {
        let context = self.context(self.hibp.id(), self.hibp.name(), CancellationToken::new(), Arc::new(RequestStats::default()));
        let breaches = self.hibp.catalog(&context, None).await?;
        let storage = self.storage();
        storage.upsert_incidents(&breaches).await?;
        Ok(breaches.len() as u64)
    }

    // -----------------------------------------------------------------------
    // Security auditing
    // -----------------------------------------------------------------------

    /// Pwned Passwords k-anonymity check. The password is never stored,
    /// logged, or transmitted; only the 5-character hash prefix is sent.
    pub async fn check_password(&self, password: Zeroizing<Vec<u8>>) -> SpectreResult<PasswordCheckResult> {
        let result = self.pwned_passwords.check(&self.http, &CancellationToken::new(), &RequestStats::default(), &password).await?;
        self.storage().record_audit(None, "password_check", serde_json::json!({})).await?;
        Ok(result)
    }

    pub async fn hash_inventory(&self, input: Zeroizing<String>) -> SpectreResult<HashInventory> {
        if input.len() > 64 * 1024 * 1024 {
            return Err(SpectreError::invalid_input("hash input exceeds 64 MiB"));
        }
        let inventory = spectre_audit::inventory(&input);
        self.storage()
            .record_audit(
                None,
                "hash_inventory",
                serde_json::json!({ "hashes_analyzed": inventory.hashes_analyzed, "overall": inventory.overall }),
            )
            .await?;
        Ok(inventory)
    }

    // -----------------------------------------------------------------------
    // Settings & providers
    // -----------------------------------------------------------------------

    pub async fn update_settings(&self, settings: EngineSettings) -> SpectreResult<EngineSettings> {
        settings.validate()?;
        let storage = self.storage();
        storage.save_settings(&settings).await?;
        self.http.update_settings(HttpSettings::from(&settings));
        let previous = self.settings();
        if previous.max_concurrency != settings.max_concurrency {
            *self.concurrency.write().unwrap_or_else(|poisoned| poisoned.into_inner()) =
                Arc::new(Semaphore::new(settings.max_concurrency as usize));
        }
        for provider in &self.providers {
            let limit = self
                .provider_configs
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(provider.id())
                .and_then(|config| config.rate_limit_per_minute)
                .unwrap_or_else(|| provider.default_rate_limit_per_minute());
            self.http.set_rate_limit(provider.id(), Some(limit));
        }
        *self.settings.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = settings.clone();
        storage.record_audit(None, "settings_updated", serde_json::to_value(&settings).unwrap_or_default()).await?;
        Ok(settings)
    }

    pub fn provider_statuses(&self) -> Vec<ProviderStatus> {
        let configs = self.provider_configs.read().unwrap_or_else(|poisoned| poisoned.into_inner());
        self.providers
            .iter()
            .map(|provider| {
                let descriptor = provider.descriptor();
                let config = configs.get(provider.id());
                let credential_configured = match &descriptor.credential {
                    spectre_core::provider::CredentialRequirement::None => false,
                    spectre_core::provider::CredentialRequirement::Optional { credential_id, .. }
                    | spectre_core::provider::CredentialRequirement::Required { credential_id, .. } => {
                        self.credentials.contains(credential_id)
                    }
                };
                ProviderStatus {
                    enabled: config.is_none_or(|config| config.enabled),
                    rate_limit_per_minute: config
                        .and_then(|config| config.rate_limit_per_minute)
                        .unwrap_or_else(|| provider.default_rate_limit_per_minute()),
                    credential_configured,
                    descriptor,
                }
            })
            .collect()
    }

    pub fn service_statuses(&self) -> Vec<ServiceStatus> {
        vec![
            ServiceStatus {
                id: "hibp".into(),
                name: "Have I Been Pwned account breaches".into(),
                description: "Breaches for ownership-verified email addresses. Requires a paid HIBP API key.".into(),
                credential_id: Some(spectre_core::credentials::ids::HIBP_API_KEY.into()),
                credential_required: true,
                credential_configured: self.credentials.contains(spectre_core::credentials::ids::HIBP_API_KEY),
                hosts: self.hibp.allowed_hosts(),
            },
            ServiceStatus {
                id: "pwned-passwords".into(),
                name: "Pwned Passwords".into(),
                description: "k-anonymity password exposure checks. Free; no key required.".into(),
                credential_id: None,
                credential_required: false,
                credential_configured: false,
                hosts: vec![self.pwned_passwords.host()],
            },
        ]
    }

    pub async fn update_provider(&self, config: ProviderConfig) -> SpectreResult<ProviderStatus> {
        config.validate()?;
        let provider = self
            .providers
            .iter()
            .find(|provider| provider.id() == config.provider_id)
            .ok_or_else(|| SpectreError::not_found(format!("provider '{}' does not exist", config.provider_id)))?;
        self.storage().save_provider_config(&config).await?;
        self.http
            .set_rate_limit(provider.id(), Some(config.rate_limit_per_minute.unwrap_or_else(|| provider.default_rate_limit_per_minute())));
        self.provider_configs.write().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(config.provider_id.clone(), config.clone());
        self.provider_statuses()
            .into_iter()
            .find(|status| status.descriptor.id == config.provider_id)
            .ok_or_else(|| SpectreError::internal("provider vanished"))
    }

    // -----------------------------------------------------------------------
    // Maintenance
    // -----------------------------------------------------------------------

    pub async fn diagnostics(&self) -> SpectreResult<Diagnostics> {
        let totals = self.http.totals();
        Ok(Diagnostics {
            engine_version: ENGINE_VERSION.into(),
            storage: self.storage().info().await?,
            providers: self.providers.len(),
            active_investigations: self.active_ids().len(),
            http_requests: totals.requests,
            cache_hits: totals.cache_hits,
            cache_misses: totals.cache_misses,
            cache_entries: self.http.cache_len(),
            retries: totals.retries,
            allowed_hosts: self.http.policy().allowed_hosts(),
            credentials_configured: self.credentials.configured_ids(),
            uptime_seconds: self.started_at.elapsed().as_secs(),
        })
    }

    pub async fn purge(&self, older_than_days: u32) -> SpectreResult<u64> {
        let storage = self.storage();
        let cutoff = Utc::now() - chrono::Duration::days(i64::from(older_than_days));
        let purged = storage.purge_before(cutoff).await?;
        storage.record_audit(None, "manual_purge", serde_json::json!({ "older_than_days": older_than_days, "purged": purged })).await?;
        Ok(purged)
    }

    pub async fn backup(&self, destination: &str) -> SpectreResult<()> {
        let storage = self.storage();
        storage.backup_to(std::path::Path::new(destination)).await?;
        storage.record_audit(None, "backup_created", serde_json::json!({})).await
    }

    /// Replace the database with a validated backup. Refused while
    /// investigations are running.
    pub async fn restore(&self, source: &str) -> SpectreResult<()> {
        if !self.active_ids().is_empty() {
            return Err(SpectreError::invalid_input("stop running investigations before restoring a backup"));
        }
        let source = PathBuf::from(source);
        Storage::validate_backup(&source).await?;
        let current = self.storage();
        let path =
            current.path().map(PathBuf::from).ok_or_else(|| SpectreError::invalid_input("in-memory databases cannot be restored"))?;
        current.close().await;
        for suffix in ["-wal", "-shm"] {
            let sidecar = PathBuf::from(format!("{}{suffix}", path.display()));
            if sidecar.exists() {
                std::fs::remove_file(&sidecar).map_err(|error| SpectreError::storage(format!("cannot remove {suffix} file: {error}")))?;
            }
        }
        std::fs::copy(&source, &path).map_err(|error| SpectreError::storage(format!("restore copy failed: {error}")))?;
        let reopened = Storage::open(&path).await?;
        reopened.record_audit(None, "backup_restored", serde_json::json!({})).await?;
        *self.storage.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = Arc::new(reopened);
        Ok(())
    }

    /// Cancel everything and wait briefly for tasks to stop.
    pub async fn shutdown(&self) {
        for investigation_id in self.active_ids() {
            self.cancel_investigation(investigation_id);
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        while !self.active_ids().is_empty() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        self.storage().close().await;
    }
}

pub(crate) fn not_cancelled(error: &SpectreError) -> bool {
    error.code != ErrorCode::Cancelled
}

#[cfg(test)]
mod tests;

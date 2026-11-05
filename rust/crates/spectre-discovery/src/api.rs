//! JSON method dispatcher shared by the FFI and CLI.
//!
//! Every method takes a JSON object and returns a JSON value. Errors are
//! structured [`SpectreError`]s with stable codes.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use spectre_core::config::{EngineSettings, ProviderConfig};
use spectre_core::error::{SpectreError, SpectreResult};
use spectre_core::model::InvestigatorDecision;
use spectre_core::target::{InvestigationTarget, TargetType, normalize_phone};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{Engine, StartInvestigationRequest, findings_csv};

fn params<T: DeserializeOwned>(value: Value) -> SpectreResult<T> {
    serde_json::from_value(if value.is_null() { json!({}) } else { value })
        .map_err(|error| SpectreError::invalid_input(format!("invalid parameters: {error}")))
}

fn to_value<T: serde::Serialize>(value: T) -> SpectreResult<Value> {
    serde_json::to_value(value).map_err(|error| SpectreError::internal(format!("serialization failed: {error}")))
}

#[derive(Deserialize)]
struct IdParams {
    id: Uuid,
}

#[derive(Deserialize)]
struct ListParams {
    #[serde(default = "default_limit")]
    limit: u32,
    #[serde(default)]
    offset: u32,
    #[serde(default)]
    search: Option<String>,
}

fn default_limit() -> u32 {
    100
}

#[derive(Deserialize)]
struct EventParams {
    id: Uuid,
    #[serde(default = "default_max_events")]
    max_events: usize,
    #[serde(default = "default_timeout")]
    timeout_ms: u64,
}

fn default_max_events() -> usize {
    256
}

fn default_timeout() -> u64 {
    250
}

#[derive(Deserialize)]
struct DecisionParams {
    relationship_id: Uuid,
    decision: Option<InvestigatorDecision>,
}

#[derive(Deserialize)]
struct EmailParams {
    email: String,
}

#[derive(Deserialize)]
struct AttestParams {
    email: String,
    statement: String,
}

#[derive(Deserialize)]
struct DomainParams {
    domain: String,
}

#[derive(Deserialize)]
struct BreachLookupParams {
    email: String,
    #[serde(default)]
    investigation_id: Option<Uuid>,
}

#[derive(Deserialize)]
struct SearchParams {
    #[serde(default)]
    query: Option<String>,
    #[serde(default = "default_catalog_limit")]
    limit: u32,
}

fn default_catalog_limit() -> u32 {
    200
}

#[derive(Deserialize)]
struct CredentialParams {
    credential_id: String,
    #[serde(default)]
    secret: Option<String>,
}

#[derive(Deserialize)]
struct ValidateParams {
    target_type: TargetType,
    value: String,
    #[serde(default)]
    default_region: Option<String>,
}

#[derive(Deserialize)]
struct PathParams {
    path: String,
}

#[derive(Deserialize)]
struct PurgeParams {
    older_than_days: u32,
}

#[derive(Deserialize)]
struct InventoryParams {
    text: String,
}

#[derive(Deserialize)]
struct BundleParams {
    bundle: spectre_storage::InvestigationBundle,
}

#[derive(Deserialize)]
struct AuditParams {
    #[serde(default = "default_limit")]
    limit: u32,
}

impl Engine {
    /// Dispatch a JSON API call.
    pub async fn call(self: &Arc<Self>, method: &str, parameters: Value) -> SpectreResult<Value> {
        match method {
            "engine.version" => Ok(json!({ "engine_version": crate::ENGINE_VERSION })),
            "engine.diagnostics" => to_value(self.diagnostics().await?),
            "dashboard.stats" => to_value(self.storage().dashboard().await?),

            "target.validate" => {
                let request: ValidateParams = params(parameters)?;
                match InvestigationTarget::parse_with_region(request.target_type, &request.value, request.default_region.as_deref()) {
                    Ok(target) => {
                        let phone = match &target {
                            InvestigationTarget::Phone(e164) => Some(normalize_phone(e164, None)?),
                            _ => None,
                        };
                        Ok(json!({ "valid": true, "normalized": target.value(), "phone": phone, "error": null }))
                    }
                    Err(error) => Ok(json!({ "valid": false, "normalized": null, "phone": null, "error": error.message })),
                }
            }

            "investigation.start" => to_value(self.start_investigation(params::<StartInvestigationRequest>(parameters)?).await?),
            "investigation.cancel" => {
                let request: IdParams = params(parameters)?;
                Ok(json!({ "cancelled": self.cancel_investigation(request.id) }))
            }
            "investigation.get" => to_value(self.storage().detail(params::<IdParams>(parameters)?.id).await?),
            "investigation.list" => {
                let request: ListParams = params(parameters)?;
                to_value(self.storage().list_investigations(request.limit, request.offset, request.search.as_deref()).await?)
            }
            "investigation.delete" => {
                self.delete_investigation(params::<IdParams>(parameters)?.id).await?;
                Ok(json!({ "deleted": true }))
            }
            "investigation.events" => {
                let request: EventParams = params(parameters)?;
                let engine = Arc::clone(self);
                let batch = tokio::task::spawn_blocking(move || {
                    engine.events.wait(request.id, request.max_events, Duration::from_millis(request.timeout_ms.min(5_000)))
                })
                .await
                .map_err(|_| SpectreError::internal("event wait failed"))?;
                to_value(batch)
            }
            "investigation.correlate" => to_value(self.correlate(params::<IdParams>(parameters)?.id).await?),
            "investigation.export_json" => to_value(self.storage().export_bundle(params::<IdParams>(parameters)?.id).await?),
            "investigation.export_csv" => {
                let request: IdParams = params(parameters)?;
                let storage = self.storage();
                let detail = storage.detail(request.id).await?;
                storage.record_audit(Some(request.id), "investigation_exported", json!({ "format": "csv" })).await?;
                Ok(json!({ "csv": findings_csv(&detail) }))
            }
            "investigation.import" => {
                let request: BundleParams = params(parameters)?;
                let storage = self.storage();
                let identifier = storage.import_bundle(&request.bundle).await?;
                storage.record_audit(Some(identifier), "investigation_imported", json!({})).await?;
                Ok(json!({ "id": identifier }))
            }
            "relationship.decide" => {
                let request: DecisionParams = params(parameters)?;
                to_value(self.decide_relationship(request.relationship_id, request.decision).await?)
            }

            "verification.list" => {
                let storage = self.storage();
                Ok(json!({ "emails": storage.list_emails().await?, "domains": storage.list_domains().await? }))
            }
            "verification.email.attest" => {
                let request: AttestParams = params(parameters)?;
                to_value(self.attest_email(&request.email, &request.statement).await?)
            }
            "verification.email.revoke" => to_value(self.revoke_email(&params::<EmailParams>(parameters)?.email).await?),
            "verification.domain.start" => to_value(self.start_domain_verification(&params::<DomainParams>(parameters)?.domain).await?),
            "verification.domain.check" => to_value(self.check_domain_verification(&params::<DomainParams>(parameters)?.domain).await?),

            "breach.lookup" => {
                let request: BreachLookupParams = params(parameters)?;
                to_value(self.lookup_breaches(&request.email, request.investigation_id).await?)
            }
            "breach.exposures" => to_value(self.stored_exposures(&params::<EmailParams>(parameters)?.email).await?),
            "breach.catalog.refresh" => Ok(json!({ "breaches": self.refresh_breach_catalog().await? })),
            "breach.catalog.search" => {
                let request: SearchParams = params(parameters)?;
                let storage = self.storage();
                Ok(json!({
                    "total": storage.catalog_size().await?,
                    "breaches": storage.search_incidents(request.query.as_deref(), request.limit).await?,
                }))
            }

            "audit.hash_inventory" => {
                let request: InventoryParams = params(parameters)?;
                to_value(self.hash_inventory(Zeroizing::new(request.text)).await?)
            }
            "audit.events" => to_value(self.storage().audit_events(params::<AuditParams>(parameters)?.limit).await?),

            "settings.get" => to_value(self.settings()),
            "settings.update" => to_value(self.update_settings(params::<EngineSettings>(parameters)?).await?),
            "providers.list" => Ok(json!({ "providers": self.provider_statuses(), "services": self.service_statuses() })),
            "providers.update" => to_value(self.update_provider(params::<ProviderConfig>(parameters)?).await?),
            "credentials.set" => {
                let request: CredentialParams = params(parameters)?;
                let secret = Zeroizing::new(request.secret.unwrap_or_default());
                self.credentials.set(&request.credential_id, secret);
                Ok(json!({ "configured": self.credentials.configured_ids() }))
            }
            "credentials.clear" => {
                self.credentials.remove(&params::<CredentialParams>(parameters)?.credential_id);
                Ok(json!({ "configured": self.credentials.configured_ids() }))
            }
            "credentials.status" => Ok(json!({ "configured": self.credentials.configured_ids() })),

            "privacy.purge" => Ok(json!({ "purged": self.purge(params::<PurgeParams>(parameters)?.older_than_days).await? })),
            "storage.info" => to_value(self.storage().info().await?),
            "storage.integrity_check" => Ok(json!({ "results": self.storage().integrity_check().await? })),
            "storage.vacuum" => {
                self.storage().vacuum().await?;
                Ok(json!({ "vacuumed": true }))
            }
            "storage.backup" => {
                self.backup(&params::<PathParams>(parameters)?.path).await?;
                Ok(json!({ "backed_up": true }))
            }
            "storage.restore" => {
                self.restore(&params::<PathParams>(parameters)?.path).await?;
                Ok(json!({ "restored": true }))
            }
            other => Err(SpectreError::invalid_input(format!("unknown method '{other}'"))),
        }
    }
}

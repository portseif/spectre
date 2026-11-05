//! The provider contract.
//!
//! A provider is an independent intelligence source. The investigation engine
//! only depends on this trait, so new sources are added by implementing it and
//! registering the provider. The engine itself does not change.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::credentials::CredentialStore;
use crate::error::SpectreResult;
use crate::http::{HttpClient, HttpRequest, HttpResponse, RequestStats};
use crate::model::{Confidence, DiscoveryMethod, FindingData, SourceReference, VerificationStatus};
use crate::target::{InvestigationTarget, TargetType};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCapability {
    ProfileLookup,
    LinkedAccounts,
    PublicEmailAssociation,
    EmailIntelligence,
    PhoneMetadata,
    DnsRecords,
    DomainRegistration,
    WebPresence,
    BreachMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CredentialRequirement {
    None,
    Optional { credential_id: String, purpose: String },
    Required { credential_id: String, purpose: String },
}

/// Static, serializable description of a provider for settings UIs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderDescriptor {
    pub id: String,
    pub name: String,
    pub description: String,
    pub homepage: String,
    pub supported_targets: Vec<TargetType>,
    pub capabilities: Vec<ProviderCapability>,
    pub credential: CredentialRequirement,
    pub allowed_hosts: Vec<String>,
    pub default_rate_limit_per_minute: u32,
    /// Provider sends requests over the network (false for offline metadata).
    pub uses_network: bool,
}

/// A finding as produced by a provider, before the engine assigns identifiers.
#[derive(Debug, Clone, PartialEq)]
pub struct FindingDraft {
    pub title: String,
    pub summary: Option<String>,
    pub confidence: Confidence,
    pub verification_status: VerificationStatus,
    pub sources: Vec<SourceReference>,
    pub data: FindingData,
}

/// Runtime services available to a provider during a lookup.
#[derive(Clone)]
pub struct ProviderContext {
    pub provider_id: String,
    pub provider_name: String,
    pub http: HttpClient,
    pub credentials: Arc<CredentialStore>,
    pub cancellation: CancellationToken,
    pub stats: Arc<RequestStats>,
    /// Streams findings to the engine before the provider returns. `None`
    /// outside an investigation (tests, ad-hoc calls).
    pub sink: Option<FindingSink>,
}

/// Channel providers use to publish findings as they are found.
pub type FindingSink = tokio::sync::mpsc::UnboundedSender<(String, FindingDraft)>;

impl ProviderContext {
    /// Publish a finding immediately. Returns the draft back when there is no
    /// sink, so the caller can include it in its return value instead.
    pub fn publish(&self, draft: FindingDraft) -> Option<FindingDraft> {
        match &self.sink {
            Some(sink) => match sink.send((self.provider_id.clone(), draft)) {
                Ok(()) => None,
                Err(tokio::sync::mpsc::error::SendError((_, draft))) => Some(draft),
            },
            None => Some(draft),
        }
    }

    /// Issue a policy-checked GET request on behalf of this provider.
    pub async fn get(&self, request: HttpRequest) -> SpectreResult<HttpResponse> {
        self.http.get(request, &self.cancellation, &self.stats).await
    }

    pub fn request(&self, url: url::Url) -> HttpRequest {
        HttpRequest::new(&self.provider_id, url)
    }

    pub fn source(&self, url: Option<String>, method: DiscoveryMethod) -> SourceReference {
        SourceReference {
            provider_id: self.provider_id.clone(),
            provider_name: self.provider_name.clone(),
            url,
            method,
            retrieved_at: Utc::now(),
        }
    }
}

#[async_trait]
pub trait OsintProvider: Send + Sync {
    fn id(&self) -> &str;

    fn name(&self) -> &str;

    fn supported_targets(&self) -> Vec<TargetType>;

    fn capabilities(&self) -> Vec<ProviderCapability>;

    fn description(&self) -> &str;

    fn homepage(&self) -> &str;

    /// Hosts this provider is permitted to contact. Registered with the
    /// endpoint policy; any other destination is refused.
    fn allowed_hosts(&self) -> Vec<String>;

    fn credential_requirement(&self) -> CredentialRequirement {
        CredentialRequirement::None
    }

    fn default_rate_limit_per_minute(&self) -> u32 {
        30
    }

    fn uses_network(&self) -> bool {
        true
    }

    /// Deadline for one run, given the configured default. Providers that
    /// fan out to many hosts can ask for more time.
    fn deadline(&self, configured: Duration) -> Duration {
        configured
    }

    /// Perform discovery. Returning `Ok(vec![])` means "nothing found"; errors
    /// are reported to the investigator and never silently swallowed.
    async fn discover(&self, context: &ProviderContext, target: &InvestigationTarget) -> SpectreResult<Vec<FindingDraft>>;

    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            id: self.id().to_string(),
            name: self.name().to_string(),
            description: self.description().to_string(),
            homepage: self.homepage().to_string(),
            supported_targets: self.supported_targets(),
            capabilities: self.capabilities(),
            credential: self.credential_requirement(),
            allowed_hosts: self.allowed_hosts(),
            default_rate_limit_per_minute: self.default_rate_limit_per_minute(),
            uses_network: self.uses_network(),
        }
    }

    fn supports(&self, target_type: TargetType) -> bool {
        self.supported_targets().contains(&target_type)
    }
}

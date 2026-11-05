//! Breach intelligence.
//!
//! * [`HibpClient`] — Have I Been Pwned API v3: authorized account lookups
//!   (paid key) and the public breach catalog (no key).
//! * [`AuthorizedAccount`] — the only way to request account-specific breach
//!   data. It can be constructed solely from an ownership-verified
//!   [`EmailRecord`], so unverified addresses cannot reach the API.
//! * [`assess_risk`] — risk indicators and remediation from breach metadata.
//!
//! This crate never retrieves, stores, or displays leaked credentials. A
//! password-exposure indicator means a breach contained password data in some
//! form; it is never presented as proof that a current password is known.

mod catalog;
mod hibp;
mod risk;

pub use catalog::HibpCatalogProvider;
pub use hibp::{HIBP_ATTRIBUTION, HIBP_HOST, HibpBreach, HibpClient, strip_description};
pub use risk::assess_risk;

use async_trait::async_trait;
use spectre_core::error::{SpectreError, SpectreResult};
use spectre_core::model::{BreachIncident, EmailRecord, VerificationMethod, VerificationStatus};
use spectre_core::provider::ProviderContext;

/// An email address whose ownership has been verified. Required by every
/// account-specific breach lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedAccount {
    email: String,
    method: VerificationMethod,
}

impl AuthorizedAccount {
    pub fn from_record(record: &EmailRecord) -> SpectreResult<Self> {
        match (record.verification_status, record.verification_method) {
            (VerificationStatus::OwnershipVerified, Some(method)) => Ok(Self { email: record.email.clone(), method }),
            _ => Err(SpectreError::authorization_required(format!(
                "{} is not ownership-verified. Verify ownership (DNS challenge or recorded attestation) before requesting account-specific breach data.",
                record.email
            ))),
        }
    }

    pub fn email(&self) -> &str {
        &self.email
    }

    pub fn method(&self) -> VerificationMethod {
        self.method
    }
}

/// Extension point for additional breach sources.
#[async_trait]
pub trait BreachProvider: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn allowed_hosts(&self) -> Vec<String>;
    fn attribution(&self) -> &str;

    /// Breaches containing an ownership-verified account.
    async fn account_breaches(&self, context: &ProviderContext, account: &AuthorizedAccount) -> SpectreResult<Vec<BreachIncident>>;

    /// Public breach metadata, optionally filtered to one service domain.
    async fn catalog(&self, context: &ProviderContext, domain: Option<&str>) -> SpectreResult<Vec<BreachIncident>>;
}

#[cfg(test)]
mod tests;

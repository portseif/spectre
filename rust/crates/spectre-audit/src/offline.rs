//! Isolated interface for a future offline password-hash auditing backend.
//!
//! **No implementation ships with Spectre.** This module only fixes the
//! contract so a backend can be added later without touching discovery,
//! breach, or correlation code. Any implementation must:
//!
//! * run only on hashes an authorized administrator supplies for systems they
//!   own or have written permission to test (recorded in [`AuditAuthorization`]);
//! * report aggregate results only — never plaintext passwords, never which
//!   specific account matched which candidate;
//! * never accept third-party breach datasets as input;
//! * remain separate from username/email discovery.
//!
//! `defuse/preimage` was evaluated as a candidate backend (see
//! `docs/security.md`): it handles only unsalted fast hashes, is unreviewed,
//! and has a single maintainer, so it is not a dependency.

use serde::{Deserialize, Serialize};
use spectre_core::error::{ErrorCode, SpectreError, SpectreResult};

use crate::hash_inventory::HashScheme;

/// Who authorized the audit and for what scope. Required for every run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditAuthorization {
    pub authorized_by: String,
    pub system_owner: String,
    pub scope: String,
    pub reference: Option<String>,
}

impl AuditAuthorization {
    pub fn validate(&self) -> SpectreResult<()> {
        if [&self.authorized_by, &self.system_owner, &self.scope].iter().any(|field| field.trim().is_empty()) {
            return Err(SpectreError::authorization_required("authorized_by, system_owner and scope are required"));
        }
        Ok(())
    }
}

/// Aggregate-only outcome of an offline audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineAuditSummary {
    pub hashes_examined: u64,
    pub weak_password_matches: u64,
    pub schemes_examined: Vec<HashScheme>,
}

pub trait OfflineAuditBackend: Send + Sync {
    fn name(&self) -> &str;
    fn supported_schemes(&self) -> &[HashScheme];
    fn audit(&self, authorization: &AuditAuthorization, hashes: &[&str]) -> SpectreResult<OfflineAuditSummary>;
}

/// The only backend available: refuses with an explanatory error.
pub struct NotConfigured;

impl OfflineAuditBackend for NotConfigured {
    fn name(&self) -> &str {
        "not configured"
    }

    fn supported_schemes(&self) -> &[HashScheme] {
        &[]
    }

    fn audit(&self, authorization: &AuditAuthorization, _hashes: &[&str]) -> SpectreResult<OfflineAuditSummary> {
        authorization.validate()?;
        Err(SpectreError::new(ErrorCode::InvalidInput, "no offline audit backend is configured; use the hash inventory instead"))
    }
}

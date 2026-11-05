//! In-memory credential store.
//!
//! Credentials are supplied at runtime by the host (the macOS app reads them
//! from Keychain; the CLI from environment variables). They are never written
//! to disk or logs by the engine and are zeroized when replaced or dropped.

use std::collections::HashMap;
use std::fmt;
use std::sync::RwLock;

use zeroize::Zeroizing;

/// Well-known credential identifiers.
pub mod ids {
    /// Have I Been Pwned API key (`hibp-api-key` header).
    pub const HIBP_API_KEY: &str = "hibp";
    /// Optional GitHub token for higher REST rate limits.
    pub const GITHUB_TOKEN: &str = "github";
}

#[derive(Default)]
pub struct CredentialStore {
    secrets: RwLock<HashMap<String, Zeroizing<String>>>,
}

impl CredentialStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, credential_id: &str, secret: Zeroizing<String>) {
        let mut secrets = self.secrets.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        if secret.trim().is_empty() {
            secrets.remove(credential_id);
        } else {
            secrets.insert(credential_id.to_string(), secret);
        }
    }

    pub fn remove(&self, credential_id: &str) {
        self.secrets.write().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(credential_id);
    }

    /// Returns a zeroizing copy of the secret.
    pub fn get(&self, credential_id: &str) -> Option<Zeroizing<String>> {
        self.secrets
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(credential_id)
            .map(|secret| Zeroizing::new(secret.as_str().to_string()))
    }

    pub fn contains(&self, credential_id: &str) -> bool {
        self.secrets.read().unwrap_or_else(|poisoned| poisoned.into_inner()).contains_key(credential_id)
    }

    pub fn configured_ids(&self) -> Vec<String> {
        let mut identifiers: Vec<String> = self.secrets.read().unwrap_or_else(|poisoned| poisoned.into_inner()).keys().cloned().collect();
        identifiers.sort();
        identifiers
    }
}

impl fmt::Debug for CredentialStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("CredentialStore").field("configured", &self.configured_ids()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_never_contains_secrets() {
        let store = CredentialStore::new();
        store.set(ids::HIBP_API_KEY, Zeroizing::new("super-secret-value".into()));
        let rendered = format!("{store:?}");
        assert!(rendered.contains("hibp"));
        assert!(!rendered.contains("super-secret-value"));
    }

    #[test]
    fn empty_secret_clears_entry() {
        let store = CredentialStore::new();
        store.set("github", Zeroizing::new("token".into()));
        assert!(store.contains("github"));
        store.set("github", Zeroizing::new("   ".into()));
        assert!(!store.contains("github"));
    }
}

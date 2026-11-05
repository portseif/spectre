//! Public OSINT provider adapters.
//!
//! Every adapter uses a documented, public API (or offline data) and declares
//! the exact hosts it contacts. Adapters never bypass authentication, CAPTCHAs,
//! or rate limits, and never probe registration or password-reset flows.

use std::sync::Arc;

use spectre_core::provider::OsintProvider;

pub mod common;
pub mod dns;
pub mod domain;
pub mod email;
pub mod phone;
pub mod username;

/// Declares the static metadata methods of [`OsintProvider`].
#[macro_export]
macro_rules! provider_metadata {
    (
        id: $id:expr,
        name: $name:expr,
        description: $description:expr,
        homepage: $homepage:expr,
        targets: [$($target:expr),* $(,)?],
        capabilities: [$($capability:expr),* $(,)?] $(,)?
    ) => {
        fn id(&self) -> &str { $id }
        fn name(&self) -> &str { $name }
        fn description(&self) -> &str { $description }
        fn homepage(&self) -> &str { $homepage }
        fn supported_targets(&self) -> Vec<spectre_core::target::TargetType> { vec![$($target),*] }
        fn capabilities(&self) -> Vec<spectre_core::provider::ProviderCapability> { vec![$($capability),*] }
    };
}

/// The built-in provider set, in display order.
pub fn default_providers() -> Vec<Arc<dyn OsintProvider>> {
    vec![
        Arc::new(username::forges::GitHubProvider::default()),
        Arc::new(username::forges::GitLabProvider::default()),
        Arc::new(username::forges::CodebergProvider::default()),
        Arc::new(username::social::KeybaseProvider::default()),
        Arc::new(username::social::MastodonProvider::default()),
        Arc::new(username::social::BlueskyProvider::default()),
        Arc::new(username::social::HackerNewsProvider::default()),
        Arc::new(username::social::DevToProvider::default()),
        Arc::new(username::community::HuggingFaceProvider::default()),
        Arc::new(username::community::DockerHubProvider::default()),
        Arc::new(username::community::ChessComProvider::default()),
        Arc::new(username::community::LichessProvider::default()),
        Arc::new(username::community::WikipediaProvider::default()),
        Arc::new(username::sites::SiteCheckProvider::default()),
        Arc::new(email::EmailDnsProvider::default()),
        Arc::new(email::GravatarProvider::default()),
        Arc::new(email::OpenPgpProvider::default()),
        Arc::new(phone::PhoneNumberingProvider),
        Arc::new(domain::DomainDnsProvider::default()),
        Arc::new(domain::RdapProvider::default()),
        Arc::new(domain::CertSpotterProvider::default()),
        Arc::new(domain::WaybackProvider::default()),
        Arc::new(domain::WebsiteProvider),
    ]
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn provider_ids_are_unique_and_declare_hosts() {
        let providers = default_providers();
        let mut identifiers = HashSet::new();
        for provider in &providers {
            assert!(identifiers.insert(provider.id().to_string()), "duplicate id {}", provider.id());
            assert!(!provider.supported_targets().is_empty());
            if provider.uses_network() && provider.id() != "website" {
                assert!(!provider.allowed_hosts().is_empty(), "{} must declare hosts", provider.id());
            }
        }
    }
}

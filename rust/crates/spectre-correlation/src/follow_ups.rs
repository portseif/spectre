//! Suggested follow-up investigations.
//!
//! Spectre never pivots on its own. Instead it lists identifiers that the
//! findings point to (published emails, linked handles, websites, other
//! addresses on a PGP key) so the investigator can start each one
//! deliberately, with its own authorization record.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use spectre_core::model::{Finding, FindingData, LinkedAccount};
use spectre_core::target::{InvestigationTarget, TargetType};
use url::Url;
use uuid::Uuid;

use crate::email_in_user_id;

const MAX_SUGGESTIONS: usize = 50;

/// Mail providers whose domains say nothing about the account holder.
const SHARED_MAIL_DOMAINS: [&str; 16] = [
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "yahoo.com",
    "icloud.com",
    "me.com",
    "mac.com",
    "proton.me",
    "protonmail.com",
    "aol.com",
    "gmx.com",
    "gmx.de",
    "yandex.ru",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FollowUp {
    pub target_type: TargetType,
    pub value: String,
    pub reason: String,
    pub source_finding_id: Option<Uuid>,
    /// Filled in by the engine from stored investigations.
    #[serde(default)]
    pub already_investigated: bool,
}

/// Platform and handle for a profile URL on a well-known site.
pub fn handle_from_url(raw: &str) -> Option<(&'static str, String)> {
    let url = Url::parse(raw).ok()?;
    let host = url.host_str()?.trim_start_matches("www.").trim_start_matches("m.").to_ascii_lowercase();
    let segments: Vec<&str> = url.path_segments()?.filter(|segment| !segment.is_empty()).collect();
    let first = segments.first().copied()?;
    let at_handle = || first.strip_prefix('@').map(str::to_string);
    let (platform, handle) = match host.as_str() {
        "x.com" | "twitter.com" => ("X", Some(first.to_string())),
        "github.com" => ("GitHub", Some(first.to_string())),
        "gitlab.com" => ("GitLab", Some(first.to_string())),
        "codeberg.org" => ("Codeberg", Some(first.to_string())),
        "instagram.com" => ("Instagram", Some(first.to_string())),
        "facebook.com" => ("Facebook", Some(first.to_string())),
        "twitch.tv" => ("Twitch", Some(first.to_string())),
        "keybase.io" => ("Keybase", Some(first.to_string())),
        "dev.to" => ("DEV Community", Some(first.to_string())),
        "huggingface.co" => ("Hugging Face", Some(first.to_string())),
        "t.me" => ("Telegram", Some(first.to_string())),
        "linkedin.com" if first == "in" => ("LinkedIn", segments.get(1).map(|handle| handle.to_string())),
        "reddit.com" if first == "user" || first == "u" => ("Reddit", segments.get(1).map(|handle| handle.to_string())),
        "bsky.app" if first == "profile" => ("Bluesky", segments.get(1).map(|handle| handle.trim_end_matches(".bsky.social").to_string())),
        "youtube.com" | "medium.com" | "tiktok.com" | "threads.net" | "threads.com" | "mastodon.social" => ("profile", at_handle()),
        _ => return None,
    };
    let handle = handle?;
    let reserved = ["about", "explore", "settings", "login", "signup", "search", "home", "share", "intent", "hashtag", "pages", "watch"];
    (!reserved.contains(&handle.to_ascii_lowercase().as_str())).then_some((platform, handle))
}

fn website_domain(raw: &str) -> Option<String> {
    let url = Url::parse(raw).ok()?;
    if handle_from_url(raw).is_some() {
        return None;
    }
    url.host_str().map(|host| host.trim_start_matches("www.").to_string())
}

#[derive(Default)]
struct Collector {
    suggestions: BTreeMap<(TargetType, String), FollowUp>,
}

impl Collector {
    fn add(&mut self, target_type: TargetType, raw: &str, reason: String, finding: &Finding) {
        let Ok(parsed) = InvestigationTarget::parse(target_type, raw) else { return };
        let value = parsed.value().to_string();
        if target_type == TargetType::Domain && SHARED_MAIL_DOMAINS.contains(&value.as_str()) {
            return;
        }
        let key = (target_type, value.to_ascii_lowercase());
        self.suggestions.entry(key).or_insert(FollowUp {
            target_type,
            value,
            reason,
            source_finding_id: Some(finding.id),
            already_investigated: false,
        });
    }

    fn linked(&mut self, account: &LinkedAccount, origin: &str, finding: &Finding) {
        if let Some(url) = &account.url {
            if let Some((platform, handle)) = handle_from_url(url) {
                let platform = account.platform.clone().unwrap_or_else(|| platform.to_string());
                self.add(TargetType::Username, &handle, format!("{platform} account linked from {origin}"), finding);
                return;
            }
            if let Some(domain) = website_domain(url) {
                self.add(TargetType::Domain, &domain, format!("Website linked from {origin}"), finding);
                return;
            }
        }
        if let Some(handle) = &account.handle {
            let platform = account.platform.clone().unwrap_or_else(|| "another platform".into());
            self.add(TargetType::Username, handle, format!("{platform} handle linked from {origin}"), finding);
        }
    }
}

/// Identifiers worth investigating next, excluding the current target.
pub fn suggest_follow_ups(target: &InvestigationTarget, findings: &[Finding]) -> Vec<FollowUp> {
    let mut collector = Collector::default();
    if let InvestigationTarget::Email(email) = target
        && let (Some((_, domain)), Some(first)) = (email.rsplit_once('@'), findings.first())
    {
        collector.add(TargetType::Domain, domain, "Mail domain of the investigated address".into(), first);
    }
    for finding in findings {
        match &finding.data {
            FindingData::Profile(profile) => {
                let origin = format!("the {} profile", profile.platform);
                for account in &profile.linked_accounts {
                    collector.linked(account, &origin, finding);
                }
                if let Some(email) = &profile.public_email {
                    collector.add(TargetType::Email, email, format!("Published on {origin}"), finding);
                }
                if let Some(domain) = profile.website.as_deref().and_then(website_domain) {
                    collector.add(TargetType::Domain, &domain, format!("Website listed on {origin}"), finding);
                }
            }
            FindingData::EmailAssociation(association) => {
                collector.add(TargetType::Email, &association.email, association.source_description.clone(), finding);
            }
            FindingData::PgpKey(key) => {
                for email in key.user_ids.iter().filter_map(|uid| email_in_user_id(uid)) {
                    collector.add(TargetType::Email, &email, "Another confirmed user ID on the same OpenPGP key".into(), finding);
                }
            }
            FindingData::WebPresence(web) => {
                for link in web.rel_me_links.iter().chain(&web.profile_links) {
                    if let Some((platform, handle)) = handle_from_url(link) {
                        collector.add(TargetType::Username, &handle, format!("{platform} account linked from the homepage"), finding);
                    }
                }
            }
            _ => {}
        }
    }
    let current = (target.target_type(), target.value().to_ascii_lowercase());
    collector.suggestions.into_iter().filter(|(key, _)| *key != current).map(|(_, suggestion)| suggestion).take(MAX_SUGGESTIONS).collect()
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use spectre_core::model::*;

    use super::*;

    fn finding(data: FindingData) -> Finding {
        Finding {
            id: Uuid::new_v4(),
            investigation_id: Uuid::new_v4(),
            provider_id: "test".into(),
            title: String::new(),
            summary: None,
            confidence: Confidence::new(0.35, ConfidenceCategory::WeakEvidence, ["x"]),
            verification_status: VerificationStatus::PubliclyObserved,
            discovered_at: Utc::now(),
            sources: Vec::new(),
            data,
        }
    }

    #[test]
    fn handles_from_profile_urls() {
        assert_eq!(handle_from_url("https://twitter.com/octo_x"), Some(("X", "octo_x".into())));
        assert_eq!(handle_from_url("https://www.linkedin.com/in/jane-doe/"), Some(("LinkedIn", "jane-doe".into())));
        assert_eq!(handle_from_url("https://bsky.app/profile/jane.bsky.social"), Some(("Bluesky", "jane".into())));
        assert_eq!(handle_from_url("https://mastodon.social/@jane"), Some(("profile", "jane".into())));
        assert_eq!(handle_from_url("https://x.com/intent/follow"), None);
        assert_eq!(handle_from_url("https://example.dev/about"), None);
    }

    #[test]
    fn suggestions_from_findings() {
        let target = InvestigationTarget::parse(TargetType::Username, "octo").unwrap();
        let profile = ProfileFinding {
            platform: "GitHub".into(),
            username: "octo".into(),
            profile_url: "https://github.com/octo".into(),
            website: Some("https://octo.dev/".into()),
            public_email: Some("Octo@Example.org".into()),
            linked_accounts: vec![
                LinkedAccount { url: Some("https://x.com/octo_x".into()), ..Default::default() },
                LinkedAccount { url: Some("https://github.com/octo".into()), ..Default::default() },
            ],
            ..Default::default()
        };
        let key = PgpKeyFinding {
            email: "octo@example.org".into(),
            fingerprint: "AB".repeat(20),
            algorithm: "Ed25519".into(),
            bits: None,
            created_at: None,
            expires_at: None,
            user_ids: vec!["Octo <octo@example.org>".into(), "Octo Work <octo@work.example.net>".into()],
            keyserver: "keys.openpgp.org".into(),
        };
        let suggestions = suggest_follow_ups(&target, &[finding(FindingData::Profile(profile)), finding(FindingData::PgpKey(key))]);
        let values: Vec<(TargetType, &str)> = suggestions.iter().map(|item| (item.target_type, item.value.as_str())).collect();
        assert!(values.contains(&(TargetType::Username, "octo_x")));
        assert!(values.contains(&(TargetType::Domain, "octo.dev")));
        assert!(values.contains(&(TargetType::Email, "octo@example.org")));
        assert!(values.contains(&(TargetType::Email, "octo@work.example.net")));
        assert!(!values.contains(&(TargetType::Username, "octo")), "the current target is excluded");
    }

    #[test]
    fn shared_mail_domains_are_not_suggested() {
        let target = InvestigationTarget::parse(TargetType::Email, "someone@gmail.com").unwrap();
        let association = EmailAssociationFinding {
            email: "someone@gmail.com".into(),
            source_description: "x".into(),
            discovery_method: DiscoveryMethod::PublicApi,
            verification_status: VerificationStatus::PubliclyObserved,
        };
        assert!(suggest_follow_ups(&target, &[finding(FindingData::EmailAssociation(association))]).is_empty());
    }
}

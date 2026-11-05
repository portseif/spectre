//! Helpers shared by provider adapters.

use std::collections::BTreeMap;

use scraper::{Html, Selector};
use spectre_core::model::{
    Confidence, ConfidenceCategory, DiscoveryMethod, EmailAssociationFinding, FindingData, LinkedAccount, ProfileFinding,
    VerificationStatus,
};
use spectre_core::provider::{FindingDraft, ProviderContext};
use url::Url;

/// Evidence weight given to a profile found only by exact username match.
/// Kept below the "Possible" threshold on purpose: a shared username alone
/// does not establish common ownership.
pub const USERNAME_MATCH_WEIGHT: f64 = 0.35;

/// Parse a compile-time constant base URL.
pub fn base_url(raw: &str) -> Url {
    Url::parse(raw).expect("provider base URL constant is valid")
}

/// Append percent-encoded path segments to a base URL.
pub fn endpoint(base: &Url, segments: &[&str]) -> Url {
    let mut url = base.clone();
    if let Ok(mut path) = url.path_segments_mut() {
        path.pop_if_empty();
        for segment in segments {
            path.push(segment);
        }
    }
    url
}

pub fn host_of(base: &Url) -> String {
    base.host_str().unwrap_or_default().to_string()
}

/// Trimmed, non-empty string or `None`.
pub fn non_empty(value: Option<&str>) -> Option<String> {
    value.map(str::trim).filter(|text| !text.is_empty()).map(str::to_string)
}

/// Plain text of an HTML fragment, whitespace-collapsed.
pub fn strip_html(html: &str) -> String {
    let fragment = Html::parse_fragment(html);
    let text: String = fragment.root_element().text().collect::<Vec<_>>().join(" ");
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// All absolute http(s) `href` targets in an HTML fragment.
pub fn extract_links(html: &str) -> Vec<String> {
    let fragment = Html::parse_fragment(html);
    let selector = Selector::parse("a[href]").expect("valid selector");
    let mut links: Vec<String> =
        fragment.select(&selector).filter_map(|anchor| anchor.value().attr("href")).filter_map(normalize_link).collect();
    links.dedup();
    links
}

/// Normalize a user-entered link: adds `https://` when no scheme is present,
/// accepts only http(s) URLs with a host.
pub fn normalize_link(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 2048 {
        return None;
    }
    let candidate = if trimmed.contains("://") { trimmed.to_string() } else { format!("https://{trimmed}") };
    let parsed = Url::parse(&candidate).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return None;
    }
    Some(parsed.to_string())
}

pub fn link(url: String) -> LinkedAccount {
    LinkedAccount { url: Some(url), ..Default::default() }
}

pub fn handle_link(platform: &str, handle: &str, url: String) -> LinkedAccount {
    LinkedAccount {
        platform: Some(platform.to_string()),
        handle: Some(handle.trim_start_matches('@').to_string()),
        url: Some(url),
        ..Default::default()
    }
}

/// Wrap a discovered profile into a finding draft with conservative confidence.
pub fn profile_draft(context: &ProviderContext, profile: ProfileFinding, api_url: &Url) -> FindingDraft {
    let summary = profile.display_name.clone().or_else(|| profile.bio.as_ref().map(|bio| truncate(bio, 140)));
    FindingDraft {
        title: format!("{} profile: {}", profile.platform, profile.username),
        summary,
        confidence: Confidence::new(
            USERNAME_MATCH_WEIGHT,
            ConfidenceCategory::WeakEvidence,
            [
                format!("Public {} account with a matching username exists", profile.platform),
                "A matching username alone does not establish common ownership".to_string(),
            ],
        ),
        verification_status: VerificationStatus::PubliclyObserved,
        sources: vec![
            context.source(Some(profile.profile_url.clone()), DiscoveryMethod::PublicApi),
            context.source(Some(api_url.to_string()), DiscoveryMethod::PublicApi),
        ],
        data: FindingData::Profile(profile),
    }
}

/// A publicly disclosed email published by the owner on a profile.
pub fn public_email_draft(context: &ProviderContext, platform: &str, email: &str, profile_url: &str) -> Option<FindingDraft> {
    let email = spectre_core::target::normalize_email(email).ok()?;
    if email.contains("noreply") || email.contains("no-reply") {
        return None;
    }
    Some(FindingDraft {
        title: format!("Public email on {platform} profile"),
        summary: Some(email.clone()),
        confidence: Confidence::new(
            0.6,
            ConfidenceCategory::Possible,
            [
                "The profile owner published this address on the profile",
                "Publication does not prove the profile owner controls the mailbox",
            ],
        ),
        verification_status: VerificationStatus::PubliclyObserved,
        sources: vec![context.source(Some(profile_url.to_string()), DiscoveryMethod::PublicApi)],
        data: FindingData::EmailAssociation(EmailAssociationFinding {
            email,
            source_description: format!("Published on the {platform} profile {profile_url}"),
            discovery_method: DiscoveryMethod::PublicApi,
            verification_status: VerificationStatus::PubliclyObserved,
        }),
    })
}

/// Factual, directly observed technical data (DNS, RDAP, numbering plans).
pub fn observed_fact(rationale: &str) -> Confidence {
    Confidence::new(1.0, ConfidenceCategory::Confirmed, [rationale.to_string()])
}

pub fn truncate(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        text.to_string()
    } else {
        let mut truncated: String = text.chars().take(max_chars).collect();
        truncated.push('…');
        truncated
    }
}

pub fn attributes<const N: usize>(pairs: [(&str, Option<String>); N]) -> BTreeMap<String, String> {
    pairs.into_iter().filter_map(|(key, value)| value.filter(|text| !text.is_empty()).map(|text| (key.to_string(), text))).collect()
}

pub fn unix_to_rfc3339(seconds: i64) -> Option<String> {
    chrono::DateTime::from_timestamp(seconds, 0).map(|date| date.to_rfc3339())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_percent_encodes_segments() {
        let base = base_url("https://api.example.com/v1/");
        let url = endpoint(&base, &["users", "a b/../c"]);
        assert_eq!(url.as_str(), "https://api.example.com/v1/users/a%20b%2F..%2Fc");
    }

    #[test]
    fn link_normalization() {
        assert_eq!(normalize_link("example.com/me").as_deref(), Some("https://example.com/me"));
        assert_eq!(normalize_link("javascript:alert(1)"), None);
        assert_eq!(normalize_link("ftp://example.com"), None);
        assert_eq!(normalize_link("  "), None);
    }

    #[test]
    fn html_helpers() {
        let html = r#"<p>Hi <a href="https://github.com/x" rel="me">gh</a> and <a href="javascript:x">bad</a></p>"#;
        assert_eq!(strip_html(html), "Hi gh and bad");
        assert_eq!(extract_links(html), vec!["https://github.com/x".to_string()]);
    }
}

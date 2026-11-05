//! Profile-page checks for sites without a usable public API.
//!
//! The catalog in `data/sites.json` is Spectre's own: every entry was written
//! for this project and checked live against a known account and a random
//! name before it was added. `verify_catalog` re-runs that self-test so stale
//! entries show up instead of quietly producing false positives.
//!
//! Checks are GET requests to public profile URLs only. Entries that need
//! login, custom headers, POST bodies, or would mean getting past bot
//! protection are not accepted into the catalog.

use std::collections::BTreeSet;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt;
use regex::Regex;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use spectre_core::error::{ErrorCode, SpectreError, SpectreResult};
use spectre_core::http::HttpResponse;
use spectre_core::model::{Confidence, ConfidenceCategory, DiscoveryMethod, FindingData, ProfileFinding, VerificationStatus};
use spectre_core::provider::{FindingDraft, OsintProvider, ProviderCapability, ProviderContext};
use spectre_core::target::{InvestigationTarget, TargetType};
use tokio::sync::Semaphore;
use url::Url;

use crate::common::{USERNAME_MATCH_WEIGHT, attributes, truncate};
use crate::provider_metadata;

const CATALOG_JSON: &str = include_str!("../../data/sites.json");
/// Parallel checks inside one run. Every check goes to a different host.
const PARALLEL_CHECKS: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SiteCatalog {
    pub version: u32,
    pub verified_on: String,
    pub sites: Vec<SiteDefinition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SiteDefinition {
    pub name: String,
    pub category: String,
    /// Public profile URL with a `{username}` placeholder.
    pub url: String,
    /// URL actually requested, when it differs from the profile URL (an API).
    #[serde(default)]
    pub probe: Option<String>,
    pub check: SiteCheck,
    /// Usernames the site allows. Others are skipped without a request.
    #[serde(default)]
    pub pattern: Option<String>,
    /// An account known to exist, used by the self-test.
    pub claimed: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SiteCheck {
    Status {
        #[serde(default = "default_found_statuses")]
        found: Vec<u16>,
        #[serde(default = "default_missing_statuses")]
        missing: Vec<u16>,
    },
    /// Page text decides. `{username}` in a marker is replaced first.
    Markers { found: Vec<String>, missing: Vec<String> },
}

fn default_found_statuses() -> Vec<u16> {
    vec![200]
}

fn default_missing_statuses() -> Vec<u16> {
    vec![404, 410]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckOutcome {
    Found,
    Missing,
    /// Blocked, rate limited, or an answer the definition doesn't cover.
    Inconclusive,
}

impl SiteDefinition {
    fn fill(template: &str, username: &str) -> Option<Url> {
        let encoded: String = url::form_urlencoded::byte_serialize(username.as_bytes()).collect();
        Url::parse(&template.replace("{username}", &encoded)).ok()
    }

    pub fn profile_url(&self, username: &str) -> Option<Url> {
        Self::fill(&self.url, username)
    }

    pub fn probe_url(&self, username: &str) -> Option<Url> {
        Self::fill(self.probe.as_deref().unwrap_or(&self.url), username)
    }

    pub fn host(&self) -> Option<String> {
        self.probe_url("x").and_then(|url| url.host_str().map(str::to_ascii_lowercase))
    }

    pub fn accepts(&self, username: &str) -> bool {
        match &self.pattern {
            Some(pattern) => Regex::new(pattern).is_ok_and(|regex| regex.is_match(username)),
            None => true,
        }
    }

    /// Classify a response for `username`.
    pub fn classify(&self, response: &HttpResponse, username: &str) -> CheckOutcome {
        match &self.check {
            SiteCheck::Status { found, missing } => {
                if found.contains(&response.status) {
                    CheckOutcome::Found
                } else if missing.contains(&response.status) {
                    CheckOutcome::Missing
                } else {
                    CheckOutcome::Inconclusive
                }
            }
            SiteCheck::Markers { found, missing } => {
                if !matches!(response.status, 200 | 404 | 410) {
                    return CheckOutcome::Inconclusive;
                }
                let body = response.text();
                let contains = |marker: &String| body.contains(&marker.replace("{username}", username));
                if missing.iter().any(contains) {
                    CheckOutcome::Missing
                } else if response.status == 200 && found.iter().any(contains) {
                    CheckOutcome::Found
                } else {
                    CheckOutcome::Missing
                }
            }
        }
    }
}

pub fn catalog() -> &'static SiteCatalog {
    static CATALOG: LazyLock<SiteCatalog> = LazyLock::new(|| serde_json::from_str(CATALOG_JSON).expect("embedded site catalog is valid"));
    &CATALOG
}

/// Page title and image from OpenGraph tags (sync: `Html` is not `Send`).
fn page_metadata(html: &str) -> (Option<String>, Option<String>) {
    let document = Html::parse_document(html);
    let meta = |property: &str| {
        let selector = Selector::parse(&format!(r#"meta[property="{property}"]"#)).ok()?;
        document
            .select(&selector)
            .find_map(|element| element.value().attr("content"))
            .map(|content| truncate(content.trim(), 160))
            .filter(|content| !content.is_empty())
    };
    (meta("og:title"), meta("og:image").filter(|image| image.starts_with("https://")))
}

pub struct SiteCheckProvider {
    sites: Arc<Vec<SiteDefinition>>,
}

impl Default for SiteCheckProvider {
    fn default() -> Self {
        Self { sites: Arc::new(catalog().sites.clone()) }
    }
}

impl SiteCheckProvider {
    /// A provider over a custom catalog (tests point this at a mock server).
    pub fn with_sites(sites: Vec<SiteDefinition>) -> Self {
        Self { sites: Arc::new(sites) }
    }

    async fn check(&self, context: &ProviderContext, site: &SiteDefinition, username: &str) -> SpectreResult<(CheckOutcome, HttpResponse)> {
        let url =
            site.probe_url(username).ok_or_else(|| SpectreError::invalid_input(format!("{} has an invalid URL template", site.name)))?;
        let request = context.request(url).accept("text/html,application/json;q=0.9,*/*;q=0.5");
        let response = context.get(request).await?;
        Ok((site.classify(&response, username), response))
    }

    fn draft(context: &ProviderContext, site: &SiteDefinition, username: &str, response: &HttpResponse) -> Option<FindingDraft> {
        let profile_url = site.profile_url(username)?.to_string();
        let is_html = response.header("content-type").is_some_and(|value| value.contains("html"));
        let (page_title, image) = if is_html { page_metadata(&response.text()) } else { (None, None) };
        let check = match site.check {
            SiteCheck::Status { .. } => "HTTP status",
            SiteCheck::Markers { .. } => "page content",
        };
        let profile = ProfileFinding {
            platform: site.name.clone(),
            username: username.to_string(),
            profile_url: profile_url.clone(),
            avatar_url: image,
            attributes: attributes([
                ("category", Some(site.category.clone())),
                ("detected_by", Some(check.to_string())),
                ("page_title", page_title),
                ("matched_by", Some("site_check".to_string())),
            ]),
            ..Default::default()
        };
        let method = if site.probe.is_some() { DiscoveryMethod::PublicApi } else { DiscoveryMethod::PublicWebPage };
        Some(FindingDraft {
            title: format!("{} profile: {username}", site.name),
            summary: Some(format!("Public profile page exists ({check} check)")),
            confidence: Confidence::new(
                USERNAME_MATCH_WEIGHT,
                ConfidenceCategory::WeakEvidence,
                [
                    format!("{} has a public profile at this username", site.name),
                    "Detected from the profile page response, not an API, so it can be wrong if the site changes".to_string(),
                    "A matching username alone does not establish common ownership".to_string(),
                ],
            ),
            verification_status: VerificationStatus::PubliclyObserved,
            sources: vec![context.source(Some(response.final_url.to_string()), method)],
            data: FindingData::Profile(profile),
        })
    }
}

#[async_trait]
impl OsintProvider for SiteCheckProvider {
    provider_metadata! {
        id: "site-check",
        name: "Profile Page Checks",
        description: "Checks public profile pages on 30+ sites without a usable API. Definitions are Spectre's own and self-tested.",
        homepage: "https://github.com/portseif/spectre/blob/main/docs/providers.md",
        targets: [TargetType::Username],
        capabilities: [ProviderCapability::ProfileLookup],
    }

    fn allowed_hosts(&self) -> Vec<String> {
        let hosts: BTreeSet<String> = self.sites.iter().filter_map(SiteDefinition::host).collect();
        hosts.into_iter().collect()
    }

    fn default_rate_limit_per_minute(&self) -> u32 {
        240
    }

    fn deadline(&self, configured: Duration) -> Duration {
        configured.max(Duration::from_secs(90))
    }

    async fn discover(&self, context: &ProviderContext, target: &InvestigationTarget) -> SpectreResult<Vec<FindingDraft>> {
        let InvestigationTarget::Username(username) = target else { return Ok(Vec::new()) };
        let applicable: Vec<&SiteDefinition> = self.sites.iter().filter(|site| site.accepts(username)).collect();
        let permits = Arc::new(Semaphore::new(PARALLEL_CHECKS));
        let mut checks = futures::stream::FuturesUnordered::new();
        for site in applicable.iter().copied() {
            let permits = Arc::clone(&permits);
            checks.push(async move {
                let _permit = permits.acquire_owned().await;
                (site, self.check(context, site, username).await)
            });
        }

        let mut unpublished = Vec::new();
        let mut inconclusive = Vec::new();
        while let Some((site, result)) = checks.next().await {
            match result {
                Ok((CheckOutcome::Found, response)) => {
                    if let Some(draft) = Self::draft(context, site, username, &response) {
                        unpublished.extend(context.publish(draft));
                    }
                }
                Ok((CheckOutcome::Missing, _)) => {}
                Ok((CheckOutcome::Inconclusive, response)) => inconclusive.push(format!("{} ({})", site.name, response.status)),
                Err(error) if error.code == ErrorCode::Cancelled => return Err(error),
                Err(error) => inconclusive.push(format!("{} ({:?})", site.name, error.code)),
            }
        }
        // A few blocked sites are normal; most of them failing means the
        // results can't be trusted, so say so instead of reporting a clean run.
        if !applicable.is_empty() && inconclusive.len() * 2 > applicable.len() {
            return Err(SpectreError::new(
                ErrorCode::UpstreamError,
                format!("{} of {} profile checks were inconclusive: {}", inconclusive.len(), applicable.len(), inconclusive.join(", ")),
            ));
        }
        if !inconclusive.is_empty() {
            tracing::info!(provider = "site-check", inconclusive = inconclusive.len(), "some profile checks were inconclusive");
        }
        Ok(unpublished)
    }
}

/// Result of self-testing one catalog entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteVerification {
    pub name: String,
    pub claimed: CheckOutcome,
    pub missing: CheckOutcome,
    pub passed: bool,
}

/// Re-run every entry against its known account and a random name.
pub async fn verify_catalog(context: &ProviderContext, provider: &SiteCheckProvider) -> Vec<SiteVerification> {
    let random_name = format!("zzspectre{:010x}", rand_suffix());
    let mut results = Vec::new();
    let mut checks = futures::stream::FuturesUnordered::new();
    let permits = Arc::new(Semaphore::new(PARALLEL_CHECKS));
    for site in provider.sites.iter() {
        let permits = Arc::clone(&permits);
        let random_name = random_name.clone();
        checks.push(async move {
            let _permit = permits.acquire_owned().await;
            let outcome = |result: SpectreResult<(CheckOutcome, HttpResponse)>| {
                result.map(|(outcome, _)| outcome).unwrap_or(CheckOutcome::Inconclusive)
            };
            let claimed = outcome(provider.check(context, site, &site.claimed).await);
            let missing = outcome(provider.check(context, site, &random_name).await);
            SiteVerification {
                name: site.name.clone(),
                passed: claimed == CheckOutcome::Found && missing == CheckOutcome::Missing,
                claimed,
                missing,
            }
        });
    }
    while let Some(result) = checks.next().await {
        results.push(result);
    }
    results.sort_by(|left, right| left.name.cmp(&right.name));
    results
}

fn rand_suffix() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|elapsed| elapsed.as_nanos()).unwrap_or(0));
    hasher.finish() & 0xff_ffff_ffff
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::username::tests::test_context;

    #[test]
    fn embedded_catalog_is_valid() {
        let catalog = catalog();
        assert!(catalog.sites.len() >= 30);
        let mut names = BTreeSet::new();
        for site in &catalog.sites {
            assert!(names.insert(site.name.clone()), "duplicate site {}", site.name);
            assert!(site.url.contains("{username}"), "{} url lacks placeholder", site.name);
            let probe = site.probe_url("x").unwrap();
            assert_eq!(probe.scheme(), "https", "{} must use HTTPS", site.name);
            if let Some(pattern) = &site.pattern {
                assert!(Regex::new(pattern).is_ok(), "{} pattern invalid", site.name);
                assert!(site.accepts(&site.claimed), "{} rejects its own claimed name", site.name);
            }
        }
        assert!(SiteCheckProvider::default().allowed_hosts().contains(&"soundcloud.com".to_string()));
    }

    fn site(server: &MockServer, name: &str, check: SiteCheck) -> SiteDefinition {
        SiteDefinition {
            name: name.into(),
            category: "test".into(),
            url: format!("{}/{}/{{username}}", server.uri(), name.to_lowercase()),
            probe: None,
            check,
            pattern: None,
            claimed: "known".into(),
        }
    }

    #[tokio::test]
    async fn classifies_status_and_marker_checks() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/status/octo"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                r#"<meta property="og:title" content="Octo on Status"><meta property="og:image" content="https://img.example/o.png">"#,
                "text/html",
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/markers/octo"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<div class=profile_header>octo</div>"))
            .mount(&server)
            .await;
        Mock::given(method("GET")).and(path("/blocked/octo")).respond_with(ResponseTemplate::new(403)).mount(&server).await;
        Mock::given(method("GET"))
            .and(path("/gone/octo"))
            .respond_with(ResponseTemplate::new(200).set_body_string("The specified profile could not be found"))
            .mount(&server)
            .await;
        Mock::given(method("GET")).respond_with(ResponseTemplate::new(404)).mount(&server).await;

        let markers = |found: &str, missing: &str| SiteCheck::Markers { found: vec![found.into()], missing: vec![missing.into()] };
        let status = SiteCheck::Status { found: vec![200], missing: vec![404] };
        let sites = vec![
            site(&server, "Status", status.clone()),
            site(&server, "Markers", markers("profile_header", "could not be found")),
            site(&server, "Blocked", status.clone()),
            site(&server, "Gone", markers("profile_header", "could not be found")),
            site(&server, "Absent", status),
        ];
        let provider = SiteCheckProvider::with_sites(sites);
        let context = test_context(&provider);
        let target = InvestigationTarget::parse(TargetType::Username, "octo").unwrap();
        let drafts = provider.discover(&context, &target).await.unwrap();
        let mut found: Vec<String> = drafts.iter().map(|draft| draft.title.clone()).collect();
        found.sort();
        assert_eq!(found, vec!["Markers profile: octo", "Status profile: octo"]);
        let status_profile = drafts.iter().find(|draft| draft.title.starts_with("Status")).unwrap();
        let FindingData::Profile(profile) = &status_profile.data else { panic!() };
        assert_eq!(profile.attributes.get("page_title").map(String::as_str), Some("Octo on Status"));
        assert_eq!(profile.avatar_url.as_deref(), Some("https://img.example/o.png"));
        assert_eq!(status_profile.confidence.category, ConfidenceCategory::WeakEvidence);
    }

    #[tokio::test]
    async fn mostly_inconclusive_runs_are_reported_as_errors() {
        let server = MockServer::start().await;
        Mock::given(method("GET")).respond_with(ResponseTemplate::new(429)).mount(&server).await;
        let status = SiteCheck::Status { found: vec![200], missing: vec![404] };
        let provider = SiteCheckProvider::with_sites(vec![site(&server, "One", status.clone()), site(&server, "Two", status)]);
        let target = InvestigationTarget::parse(TargetType::Username, "octo").unwrap();
        let error = provider.discover(&test_context(&provider), &target).await.unwrap_err();
        assert_eq!(error.code, ErrorCode::UpstreamError);
        assert!(error.message.contains("2 of 2"));
    }

    #[tokio::test]
    async fn patterns_skip_impossible_usernames_and_self_test_runs() {
        let server = MockServer::start().await;
        Mock::given(method("GET")).and(path("/strict/known")).respond_with(ResponseTemplate::new(200)).mount(&server).await;
        Mock::given(method("GET")).respond_with(ResponseTemplate::new(404)).mount(&server).await;
        let mut strict = site(&server, "Strict", SiteCheck::Status { found: vec![200], missing: vec![404] });
        strict.pattern = Some("^[a-z]{3,8}$".into());
        assert!(!strict.accepts("has-dash"));
        let provider = SiteCheckProvider::with_sites(vec![strict]);
        let target = InvestigationTarget::parse(TargetType::Username, "has-dash").unwrap();
        assert!(provider.discover(&test_context(&provider), &target).await.unwrap().is_empty());
        assert!(server.received_requests().await.unwrap().is_empty(), "no request for names the site can't have");

        let verification = verify_catalog(&test_context(&provider), &provider).await;
        assert_eq!(verification.len(), 1);
        assert!(verification[0].passed, "{verification:?}");
    }
}

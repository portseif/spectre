//! Community platforms: Hugging Face, Docker Hub, Chess.com, Lichess, Wikipedia.

use async_trait::async_trait;
use serde::Deserialize;
use spectre_core::error::SpectreResult;
use spectre_core::model::ProfileFinding;
use spectre_core::provider::{FindingDraft, OsintProvider, ProviderCapability, ProviderContext};
use spectre_core::target::{InvestigationTarget, TargetType};
use url::Url;

use crate::common::{attributes, base_url, endpoint, host_of, link, non_empty, normalize_link, profile_draft, strip_html, unix_to_rfc3339};
use crate::provider_metadata;

// ---------------------------------------------------------------------------
// Hugging Face — https://huggingface.co/docs/hub/api
// ---------------------------------------------------------------------------

pub struct HuggingFaceProvider {
    base: Url,
}

impl Default for HuggingFaceProvider {
    fn default() -> Self {
        Self { base: base_url("https://huggingface.co/") }
    }
}

impl HuggingFaceProvider {
    pub fn with_base(base: Url) -> Self {
        Self { base }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HuggingFaceUser {
    user: String,
    fullname: Option<String>,
    avatar_url: Option<String>,
    created_at: Option<String>,
    details: Option<String>,
    is_pro: Option<bool>,
    num_models: Option<u64>,
    num_datasets: Option<u64>,
    num_spaces: Option<u64>,
    num_followers: Option<u64>,
}

#[async_trait]
impl OsintProvider for HuggingFaceProvider {
    provider_metadata! {
        id: "huggingface",
        name: "Hugging Face",
        description: "Hugging Face Hub user overviews.",
        homepage: "https://huggingface.co",
        targets: [TargetType::Username],
        capabilities: [ProviderCapability::ProfileLookup],
    }

    fn allowed_hosts(&self) -> Vec<String> {
        vec![host_of(&self.base)]
    }

    async fn discover(&self, context: &ProviderContext, target: &InvestigationTarget) -> SpectreResult<Vec<FindingDraft>> {
        let InvestigationTarget::Username(username) = target else { return Ok(Vec::new()) };
        let url = endpoint(&self.base, &["api", "users", username, "overview"]);
        let response = context.get(context.request(url.clone())).await?;
        if response.status == 404 {
            return Ok(Vec::new());
        }
        let user: HuggingFaceUser = response.ensure_success()?.json()?;
        let profile = ProfileFinding {
            platform: "Hugging Face".to_string(),
            username: user.user.clone(),
            profile_url: format!("https://huggingface.co/{}", user.user),
            display_name: non_empty(user.fullname.as_deref()),
            bio: non_empty(user.details.as_deref()),
            avatar_url: user.avatar_url,
            account_created_at: user.created_at,
            attributes: attributes([
                ("models", user.num_models.map(|count| count.to_string())),
                ("datasets", user.num_datasets.map(|count| count.to_string())),
                ("spaces", user.num_spaces.map(|count| count.to_string())),
                ("followers", user.num_followers.map(|count| count.to_string())),
                ("pro", user.is_pro.filter(|pro| *pro).map(|_| "true".to_string())),
            ]),
            ..Default::default()
        };
        Ok(vec![profile_draft(context, profile, &url)])
    }
}

// ---------------------------------------------------------------------------
// Docker Hub — https://docs.docker.com/reference/api/hub/latest/
// ---------------------------------------------------------------------------

pub struct DockerHubProvider {
    base: Url,
}

impl Default for DockerHubProvider {
    fn default() -> Self {
        Self { base: base_url("https://hub.docker.com/") }
    }
}

impl DockerHubProvider {
    pub fn with_base(base: Url) -> Self {
        Self { base }
    }
}

#[derive(Deserialize)]
struct DockerHubUser {
    username: String,
    full_name: Option<String>,
    location: Option<String>,
    company: Option<String>,
    profile_url: Option<String>,
    date_joined: Option<String>,
    #[serde(rename = "type")]
    account_type: Option<String>,
}

#[async_trait]
impl OsintProvider for DockerHubProvider {
    provider_metadata! {
        id: "dockerhub",
        name: "Docker Hub",
        description: "Docker Hub user accounts.",
        homepage: "https://hub.docker.com",
        targets: [TargetType::Username],
        capabilities: [ProviderCapability::ProfileLookup, ProviderCapability::LinkedAccounts],
    }

    fn allowed_hosts(&self) -> Vec<String> {
        vec![host_of(&self.base)]
    }

    async fn discover(&self, context: &ProviderContext, target: &InvestigationTarget) -> SpectreResult<Vec<FindingDraft>> {
        let InvestigationTarget::Username(username) = target else { return Ok(Vec::new()) };
        let url = endpoint(&self.base, &["v2", "users", &username.to_ascii_lowercase(), ""]);
        let response = context.get(context.request(url.clone())).await?;
        if response.status == 404 || (300..400).contains(&response.status) {
            // Organisations redirect away from the users endpoint.
            return Ok(Vec::new());
        }
        let user: DockerHubUser = response.ensure_success()?.json()?;
        let website = user.profile_url.as_deref().and_then(normalize_link);
        let profile = ProfileFinding {
            platform: "Docker Hub".to_string(),
            username: user.username.clone(),
            profile_url: format!("https://hub.docker.com/u/{}", user.username),
            display_name: non_empty(user.full_name.as_deref()),
            website: website.clone(),
            location: non_empty(user.location.as_deref()),
            account_created_at: user.date_joined,
            linked_accounts: website.into_iter().map(link).collect(),
            attributes: attributes([("company", non_empty(user.company.as_deref())), ("account_type", user.account_type)]),
            ..Default::default()
        };
        Ok(vec![profile_draft(context, profile, &url)])
    }
}

// ---------------------------------------------------------------------------
// Chess.com — https://www.chess.com/news/view/published-data-api
// ---------------------------------------------------------------------------

pub struct ChessComProvider {
    base: Url,
}

impl Default for ChessComProvider {
    fn default() -> Self {
        Self { base: base_url("https://api.chess.com/") }
    }
}

impl ChessComProvider {
    pub fn with_base(base: Url) -> Self {
        Self { base }
    }
}

#[derive(Deserialize)]
struct ChessComPlayer {
    username: String,
    url: String,
    name: Option<String>,
    avatar: Option<String>,
    country: Option<String>,
    location: Option<String>,
    joined: Option<i64>,
    status: Option<String>,
    title: Option<String>,
    followers: Option<u64>,
    verified: Option<bool>,
    twitch_url: Option<String>,
}

#[async_trait]
impl OsintProvider for ChessComProvider {
    provider_metadata! {
        id: "chesscom",
        name: "Chess.com",
        description: "Chess.com player profiles via the Published-Data API.",
        homepage: "https://www.chess.com",
        targets: [TargetType::Username],
        capabilities: [ProviderCapability::ProfileLookup, ProviderCapability::LinkedAccounts],
    }

    fn allowed_hosts(&self) -> Vec<String> {
        vec![host_of(&self.base)]
    }

    async fn discover(&self, context: &ProviderContext, target: &InvestigationTarget) -> SpectreResult<Vec<FindingDraft>> {
        let InvestigationTarget::Username(username) = target else { return Ok(Vec::new()) };
        let url = endpoint(&self.base, &["pub", "player", &username.to_ascii_lowercase()]);
        let response = context.get(context.request(url.clone())).await?;
        if response.status == 404 {
            return Ok(Vec::new());
        }
        let player: ChessComPlayer = response.ensure_success()?.json()?;
        let country_code = player.country.as_deref().and_then(|country| country.rsplit('/').next()).map(str::to_string);
        let profile = ProfileFinding {
            platform: "Chess.com".to_string(),
            username: player.username,
            profile_url: player.url,
            display_name: non_empty(player.name.as_deref()),
            avatar_url: player.avatar,
            location: non_empty(player.location.as_deref()),
            account_created_at: player.joined.and_then(unix_to_rfc3339),
            platform_verified: player.verified.unwrap_or(false),
            linked_accounts: player.twitch_url.as_deref().and_then(normalize_link).into_iter().map(link).collect(),
            attributes: attributes([
                ("country", country_code),
                ("status", player.status),
                ("title", player.title),
                ("followers", player.followers.map(|count| count.to_string())),
            ]),
            ..Default::default()
        };
        Ok(vec![profile_draft(context, profile, &url)])
    }
}

// ---------------------------------------------------------------------------
// Lichess — https://lichess.org/api#tag/Users/operation/apiUser
// ---------------------------------------------------------------------------

pub struct LichessProvider {
    base: Url,
}

impl Default for LichessProvider {
    fn default() -> Self {
        Self { base: base_url("https://lichess.org/") }
    }
}

impl LichessProvider {
    pub fn with_base(base: Url) -> Self {
        Self { base }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LichessUser {
    username: String,
    url: Option<String>,
    created_at: Option<i64>,
    disabled: Option<bool>,
    tos_violation: Option<bool>,
    verified: Option<bool>,
    profile: Option<LichessProfile>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LichessProfile {
    bio: Option<String>,
    real_name: Option<String>,
    links: Option<String>,
    location: Option<String>,
    flag: Option<String>,
}

#[async_trait]
impl OsintProvider for LichessProvider {
    provider_metadata! {
        id: "lichess",
        name: "Lichess",
        description: "Lichess public user profiles, including owner-declared links.",
        homepage: "https://lichess.org",
        targets: [TargetType::Username],
        capabilities: [ProviderCapability::ProfileLookup, ProviderCapability::LinkedAccounts],
    }

    fn allowed_hosts(&self) -> Vec<String> {
        vec![host_of(&self.base)]
    }

    async fn discover(&self, context: &ProviderContext, target: &InvestigationTarget) -> SpectreResult<Vec<FindingDraft>> {
        let InvestigationTarget::Username(username) = target else { return Ok(Vec::new()) };
        let url = endpoint(&self.base, &["api", "user", username]);
        let response = context.get(context.request(url.clone())).await?;
        if response.status == 404 {
            return Ok(Vec::new());
        }
        let user: LichessUser = response.ensure_success()?.json()?;
        let profile_info = user.profile;
        let linked_accounts = profile_info
            .as_ref()
            .and_then(|info| info.links.as_deref())
            .map(|links| links.split_whitespace().filter_map(normalize_link).map(link).collect())
            .unwrap_or_default();
        let closed = user.disabled.unwrap_or(false) || user.tos_violation.unwrap_or(false);
        let profile = ProfileFinding {
            platform: "Lichess".to_string(),
            username: user.username.clone(),
            profile_url: user.url.unwrap_or_else(|| format!("https://lichess.org/@/{}", user.username)),
            display_name: non_empty(profile_info.as_ref().and_then(|info| info.real_name.as_deref())),
            bio: non_empty(profile_info.as_ref().and_then(|info| info.bio.as_deref())),
            location: non_empty(profile_info.as_ref().and_then(|info| info.location.as_deref())),
            account_created_at: user.created_at.and_then(|milliseconds| unix_to_rfc3339(milliseconds / 1000)),
            platform_verified: user.verified.unwrap_or(false),
            linked_accounts,
            attributes: attributes([
                ("flag", profile_info.as_ref().and_then(|info| info.flag.clone())),
                ("status", closed.then(|| "closed".to_string())),
            ]),
            ..Default::default()
        };
        Ok(vec![profile_draft(context, profile, &url)])
    }
}

// ---------------------------------------------------------------------------
// Wikipedia (English) — https://www.mediawiki.org/wiki/API:Users
// ---------------------------------------------------------------------------

pub struct WikipediaProvider {
    base: Url,
}

impl Default for WikipediaProvider {
    fn default() -> Self {
        Self { base: base_url("https://en.wikipedia.org/") }
    }
}

impl WikipediaProvider {
    pub fn with_base(base: Url) -> Self {
        Self { base }
    }
}

#[derive(Deserialize)]
struct MediaWikiResponse {
    query: Option<MediaWikiQuery>,
}

#[derive(Deserialize)]
struct MediaWikiQuery {
    #[serde(default)]
    users: Vec<serde_json::Value>,
}

#[async_trait]
impl OsintProvider for WikipediaProvider {
    provider_metadata! {
        id: "wikipedia",
        name: "Wikipedia (English)",
        description: "Registered English Wikipedia user accounts via the MediaWiki API.",
        homepage: "https://en.wikipedia.org",
        targets: [TargetType::Username],
        capabilities: [ProviderCapability::ProfileLookup],
    }

    fn allowed_hosts(&self) -> Vec<String> {
        vec![host_of(&self.base)]
    }

    async fn discover(&self, context: &ProviderContext, target: &InvestigationTarget) -> SpectreResult<Vec<FindingDraft>> {
        let InvestigationTarget::Username(username) = target else { return Ok(Vec::new()) };
        let mut url = endpoint(&self.base, &["w", "api.php"]);
        url.query_pairs_mut()
            .append_pair("action", "query")
            .append_pair("list", "users")
            .append_pair("ususers", username)
            .append_pair("usprop", "registration|editcount|blockinfo")
            .append_pair("format", "json");
        let parsed: MediaWikiResponse = context.get(context.request(url.clone())).await?.ensure_success()?.json()?;
        let Some(user) = parsed.query.and_then(|query| query.users.into_iter().next()) else { return Ok(Vec::new()) };
        if user.get("missing").is_some() || user.get("invalid").is_some() {
            return Ok(Vec::new());
        }
        let Some(name) = user.get("name").and_then(|value| value.as_str()) else { return Ok(Vec::new()) };
        let page_name = name.replace(' ', "_");
        let blocked = user.get("blockid").is_some();
        let profile = ProfileFinding {
            platform: "Wikipedia".to_string(),
            username: name.to_string(),
            profile_url: format!("https://en.wikipedia.org/wiki/User:{page_name}"),
            account_created_at: user.get("registration").and_then(|value| value.as_str()).map(str::to_string),
            attributes: attributes([
                ("edits", user.get("editcount").map(|value| value.to_string())),
                ("blocked", blocked.then(|| "true".to_string())),
                ("block_reason", user.get("blockreason").and_then(|value| value.as_str()).map(strip_html).filter(|_| blocked)),
            ]),
            ..Default::default()
        };
        Ok(vec![profile_draft(context, profile, &url)])
    }
}

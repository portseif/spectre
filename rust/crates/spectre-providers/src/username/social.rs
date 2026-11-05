//! Social and identity platforms: Keybase, Mastodon, Bluesky, Hacker News, DEV.

use std::sync::LazyLock;

use async_trait::async_trait;
use regex::Regex;
use serde::Deserialize;
use spectre_core::error::{ErrorCode, SpectreError, SpectreResult};
use spectre_core::model::{LinkedAccount, ProfileFinding};
use spectre_core::provider::{FindingDraft, OsintProvider, ProviderCapability, ProviderContext};
use spectre_core::target::{InvestigationTarget, TargetType};
use url::Url;

use crate::common::{
    attributes, base_url, endpoint, extract_links, handle_link, host_of, link, non_empty, normalize_link, profile_draft, strip_html,
    unix_to_rfc3339,
};
use crate::provider_metadata;

// ---------------------------------------------------------------------------
// Keybase: https://keybase.io/docs/api/1.0/call/user/lookup
// ---------------------------------------------------------------------------

static KEYBASE_USERNAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_]{2,16}$").expect("valid regex"));

pub struct KeybaseProvider {
    base: Url,
}

impl Default for KeybaseProvider {
    fn default() -> Self {
        Self { base: base_url("https://keybase.io/") }
    }
}

impl KeybaseProvider {
    pub fn with_base(base: Url) -> Self {
        Self { base }
    }
}

#[derive(Deserialize)]
struct KeybaseResponse {
    status: KeybaseStatus,
    #[serde(default)]
    them: Vec<Option<KeybaseUser>>,
}

#[derive(Deserialize)]
struct KeybaseStatus {
    code: i64,
    #[serde(default)]
    name: String,
}

#[derive(Deserialize)]
struct KeybaseUser {
    basics: KeybaseBasics,
    profile: Option<KeybaseProfile>,
    proofs_summary: Option<KeybaseProofs>,
}

#[derive(Deserialize)]
struct KeybaseBasics {
    username: String,
    ctime: Option<i64>,
}

#[derive(Deserialize)]
struct KeybaseProfile {
    full_name: Option<String>,
    location: Option<String>,
    bio: Option<String>,
}

#[derive(Deserialize)]
struct KeybaseProofs {
    #[serde(default)]
    all: Vec<KeybaseProof>,
}

#[derive(Deserialize)]
struct KeybaseProof {
    proof_type: String,
    nametag: String,
    service_url: Option<String>,
    state: Option<i64>,
}

fn keybase_platform(proof_type: &str) -> String {
    match proof_type {
        "twitter" => "X".to_string(),
        "github" => "GitHub".to_string(),
        "reddit" => "Reddit".to_string(),
        "hackernews" => "Hacker News".to_string(),
        "generic_web_site" => "Website".to_string(),
        "dns" => "Domain".to_string(),
        "facebook" => "Facebook".to_string(),
        other => other.to_string(),
    }
}

#[async_trait]
impl OsintProvider for KeybaseProvider {
    provider_metadata! {
        id: "keybase",
        name: "Keybase",
        description: "Keybase users and their cryptographically signed identity proofs.",
        homepage: "https://keybase.io",
        targets: [TargetType::Username],
        capabilities: [ProviderCapability::ProfileLookup, ProviderCapability::LinkedAccounts],
    }

    fn allowed_hosts(&self) -> Vec<String> {
        vec![host_of(&self.base)]
    }

    async fn discover(&self, context: &ProviderContext, target: &InvestigationTarget) -> SpectreResult<Vec<FindingDraft>> {
        let InvestigationTarget::Username(username) = target else { return Ok(Vec::new()) };
        if !KEYBASE_USERNAME.is_match(username) {
            // Not a valid Keybase username; nothing can exist there.
            return Ok(Vec::new());
        }
        let mut url = endpoint(&self.base, &["_", "api", "1.0", "user", "lookup.json"]);
        url.query_pairs_mut().append_pair("usernames", username).append_pair("fields", "basics,profile,proofs_summary");
        let parsed: KeybaseResponse = context.get(context.request(url.clone())).await?.ensure_success()?.json()?;
        if parsed.status.code != 0 {
            return Err(SpectreError::new(ErrorCode::UpstreamError, format!("Keybase lookup failed: {}", parsed.status.name)));
        }
        let Some(Some(user)) = parsed.them.into_iter().next() else { return Ok(Vec::new()) };
        let linked_accounts = user
            .proofs_summary
            .map(|proofs| proofs.all)
            .unwrap_or_default()
            .into_iter()
            .map(|proof| LinkedAccount {
                platform: Some(keybase_platform(&proof.proof_type)),
                handle: Some(proof.nametag.clone()),
                url: proof.service_url.as_deref().and_then(normalize_link),
                verified_by_platform: proof.state == Some(1),
                note: Some(format!("Keybase {} proof", proof.proof_type)),
            })
            .collect();
        let profile_info = user.profile;
        let profile = ProfileFinding {
            platform: "Keybase".to_string(),
            username: user.basics.username.clone(),
            profile_url: format!("https://keybase.io/{}", user.basics.username),
            display_name: non_empty(profile_info.as_ref().and_then(|info| info.full_name.as_deref())),
            bio: non_empty(profile_info.as_ref().and_then(|info| info.bio.as_deref())),
            location: non_empty(profile_info.as_ref().and_then(|info| info.location.as_deref())),
            account_created_at: user.basics.ctime.and_then(unix_to_rfc3339),
            linked_accounts,
            ..Default::default()
        };
        Ok(vec![profile_draft(context, profile, &url)])
    }
}

// ---------------------------------------------------------------------------
// Mastodon (mastodon.social): https://docs.joinmastodon.org/methods/accounts/#lookup
// ---------------------------------------------------------------------------

pub struct MastodonProvider {
    base: Url,
}

impl Default for MastodonProvider {
    fn default() -> Self {
        Self { base: base_url("https://mastodon.social/") }
    }
}

impl MastodonProvider {
    pub fn with_base(base: Url) -> Self {
        Self { base }
    }
}

#[derive(Deserialize)]
struct MastodonAccount {
    username: String,
    acct: String,
    display_name: Option<String>,
    note: Option<String>,
    url: String,
    avatar: Option<String>,
    created_at: Option<String>,
    followers_count: Option<u64>,
    statuses_count: Option<u64>,
    bot: Option<bool>,
    #[serde(default)]
    fields: Vec<MastodonField>,
}

#[derive(Deserialize)]
struct MastodonField {
    name: String,
    value: String,
    verified_at: Option<String>,
}

#[async_trait]
impl OsintProvider for MastodonProvider {
    provider_metadata! {
        id: "mastodon",
        name: "Mastodon (mastodon.social)",
        description: "Accounts on the mastodon.social instance, including rel=\"me\" verified profile links.",
        homepage: "https://mastodon.social",
        targets: [TargetType::Username],
        capabilities: [ProviderCapability::ProfileLookup, ProviderCapability::LinkedAccounts],
    }

    fn allowed_hosts(&self) -> Vec<String> {
        vec![host_of(&self.base)]
    }

    async fn discover(&self, context: &ProviderContext, target: &InvestigationTarget) -> SpectreResult<Vec<FindingDraft>> {
        let InvestigationTarget::Username(username) = target else { return Ok(Vec::new()) };
        let mut url = endpoint(&self.base, &["api", "v1", "accounts", "lookup"]);
        url.query_pairs_mut().append_pair("acct", username);
        let response = context.get(context.request(url.clone())).await?;
        if response.status == 404 {
            return Ok(Vec::new());
        }
        let account: MastodonAccount = response.ensure_success()?.json()?;
        let mut linked_accounts: Vec<LinkedAccount> = Vec::new();
        for field in &account.fields {
            for href in extract_links(&field.value) {
                linked_accounts.push(LinkedAccount {
                    url: Some(href),
                    verified_by_platform: field.verified_at.is_some(),
                    note: Some(match &field.verified_at {
                        Some(_) => format!("Profile field \"{}\" (rel=\"me\" verified by the instance)", field.name),
                        None => format!("Profile field \"{}\"", field.name),
                    }),
                    ..Default::default()
                });
            }
        }
        if let Some(note) = &account.note {
            for href in extract_links(note) {
                if !linked_accounts.iter().any(|existing| existing.url.as_deref() == Some(href.as_str())) {
                    linked_accounts.push(link(href));
                }
            }
        }
        let profile = ProfileFinding {
            platform: "Mastodon".to_string(),
            username: account.acct.clone(),
            profile_url: account.url,
            display_name: non_empty(account.display_name.as_deref()),
            bio: account.note.as_deref().map(strip_html).filter(|text| !text.is_empty()),
            avatar_url: account.avatar,
            account_created_at: account.created_at,
            linked_accounts,
            attributes: attributes([
                ("instance", Some(host_of(&self.base))),
                ("local_username", Some(account.username)),
                ("followers", account.followers_count.map(|count| count.to_string())),
                ("posts", account.statuses_count.map(|count| count.to_string())),
                ("bot", account.bot.filter(|is_bot| *is_bot).map(|_| "true".to_string())),
            ]),
            ..Default::default()
        };
        Ok(vec![profile_draft(context, profile, &url)])
    }
}

// ---------------------------------------------------------------------------
// Bluesky: https://docs.bsky.app/docs/api/app-bsky-actor-get-profile
// ---------------------------------------------------------------------------

static BLUESKY_HANDLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$").expect("valid regex"));

pub struct BlueskyProvider {
    base: Url,
}

impl Default for BlueskyProvider {
    fn default() -> Self {
        Self { base: base_url("https://public.api.bsky.app/") }
    }
}

impl BlueskyProvider {
    pub fn with_base(base: Url) -> Self {
        Self { base }
    }

    /// `alice` becomes `alice.bsky.social`; dotted names are treated as full handles.
    pub fn handle_for(username: &str) -> Option<String> {
        let lowered = username.to_ascii_lowercase();
        let handle = if lowered.contains('.') { lowered } else { format!("{lowered}.bsky.social") };
        BLUESKY_HANDLE.is_match(&handle).then_some(handle)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BlueskyProfile {
    did: String,
    handle: String,
    display_name: Option<String>,
    description: Option<String>,
    avatar: Option<String>,
    created_at: Option<String>,
    followers_count: Option<u64>,
    posts_count: Option<u64>,
    verification: Option<BlueskyVerification>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BlueskyVerification {
    verified_status: Option<String>,
}

#[derive(Deserialize)]
struct XrpcError {
    error: Option<String>,
    message: Option<String>,
}

#[async_trait]
impl OsintProvider for BlueskyProvider {
    provider_metadata! {
        id: "bluesky",
        name: "Bluesky",
        description: "Bluesky profiles via the public AppView API (handle <username>.bsky.social).",
        homepage: "https://bsky.app",
        targets: [TargetType::Username],
        capabilities: [ProviderCapability::ProfileLookup],
    }

    fn allowed_hosts(&self) -> Vec<String> {
        vec![host_of(&self.base)]
    }

    async fn discover(&self, context: &ProviderContext, target: &InvestigationTarget) -> SpectreResult<Vec<FindingDraft>> {
        let InvestigationTarget::Username(username) = target else { return Ok(Vec::new()) };
        let Some(handle) = Self::handle_for(username) else { return Ok(Vec::new()) };
        let mut url = endpoint(&self.base, &["xrpc", "app.bsky.actor.getProfile"]);
        url.query_pairs_mut().append_pair("actor", &handle);
        let response = context.get(context.request(url.clone())).await?;
        if response.status == 400 {
            let error: XrpcError = response.json().unwrap_or(XrpcError { error: None, message: None });
            let message = error.message.unwrap_or_default();
            if message.to_ascii_lowercase().contains("not found") || error.error.as_deref() == Some("InvalidRequest") {
                return Ok(Vec::new());
            }
            return Err(SpectreError::new(ErrorCode::UpstreamError, format!("Bluesky rejected the lookup: {message}")));
        }
        let profile: BlueskyProfile = response.ensure_success()?.json()?;
        let finding = ProfileFinding {
            platform: "Bluesky".to_string(),
            username: profile.handle.clone(),
            profile_url: format!("https://bsky.app/profile/{}", profile.handle),
            display_name: non_empty(profile.display_name.as_deref()),
            bio: non_empty(profile.description.as_deref()),
            avatar_url: profile.avatar,
            account_created_at: profile.created_at,
            platform_verified: profile.verification.and_then(|verification| verification.verified_status).as_deref() == Some("valid"),
            attributes: attributes([
                ("did", Some(profile.did)),
                ("followers", profile.followers_count.map(|count| count.to_string())),
                ("posts", profile.posts_count.map(|count| count.to_string())),
            ]),
            ..Default::default()
        };
        Ok(vec![profile_draft(context, finding, &url)])
    }
}

// ---------------------------------------------------------------------------
// Hacker News: https://github.com/HackerNews/API
// ---------------------------------------------------------------------------

pub struct HackerNewsProvider {
    base: Url,
}

impl Default for HackerNewsProvider {
    fn default() -> Self {
        Self { base: base_url("https://hacker-news.firebaseio.com/") }
    }
}

impl HackerNewsProvider {
    pub fn with_base(base: Url) -> Self {
        Self { base }
    }
}

#[derive(Deserialize)]
struct HackerNewsUser {
    id: String,
    created: Option<i64>,
    karma: Option<i64>,
    about: Option<String>,
}

#[async_trait]
impl OsintProvider for HackerNewsProvider {
    provider_metadata! {
        id: "hackernews",
        name: "Hacker News",
        description: "Hacker News user profiles via the official Firebase API (usernames are case-sensitive).",
        homepage: "https://news.ycombinator.com",
        targets: [TargetType::Username],
        capabilities: [ProviderCapability::ProfileLookup, ProviderCapability::LinkedAccounts],
    }

    fn allowed_hosts(&self) -> Vec<String> {
        vec![host_of(&self.base)]
    }

    async fn discover(&self, context: &ProviderContext, target: &InvestigationTarget) -> SpectreResult<Vec<FindingDraft>> {
        let InvestigationTarget::Username(username) = target else { return Ok(Vec::new()) };
        let url = endpoint(&self.base, &["v0", "user", &format!("{username}.json")]);
        let response = context.get(context.request(url.clone())).await?.ensure_success()?;
        let Some(user) = response.json::<Option<HackerNewsUser>>()? else { return Ok(Vec::new()) };
        let about = user.about.as_deref().map(strip_html).filter(|text| !text.is_empty());
        let profile = ProfileFinding {
            platform: "Hacker News".to_string(),
            username: user.id.clone(),
            profile_url: format!("https://news.ycombinator.com/user?id={}", user.id),
            bio: about,
            account_created_at: user.created.and_then(unix_to_rfc3339),
            linked_accounts: user.about.as_deref().map(extract_links).unwrap_or_default().into_iter().map(link).collect(),
            attributes: attributes([("karma", user.karma.map(|karma| karma.to_string()))]),
            ..Default::default()
        };
        Ok(vec![profile_draft(context, profile, &url)])
    }
}

// ---------------------------------------------------------------------------
// DEV Community: https://developers.forem.com/api/v1#tag/users
// ---------------------------------------------------------------------------

pub struct DevToProvider {
    base: Url,
}

impl Default for DevToProvider {
    fn default() -> Self {
        Self { base: base_url("https://dev.to/") }
    }
}

impl DevToProvider {
    pub fn with_base(base: Url) -> Self {
        Self { base }
    }
}

#[derive(Deserialize)]
struct DevToUser {
    username: String,
    name: Option<String>,
    summary: Option<String>,
    twitter_username: Option<String>,
    github_username: Option<String>,
    website_url: Option<String>,
    location: Option<String>,
    joined_at: Option<String>,
    profile_image: Option<String>,
}

#[async_trait]
impl OsintProvider for DevToProvider {
    provider_metadata! {
        id: "devto",
        name: "DEV Community",
        description: "DEV (dev.to) profiles with owner-declared GitHub, X, and website links.",
        homepage: "https://dev.to",
        targets: [TargetType::Username],
        capabilities: [ProviderCapability::ProfileLookup, ProviderCapability::LinkedAccounts],
    }

    fn allowed_hosts(&self) -> Vec<String> {
        vec![host_of(&self.base)]
    }

    async fn discover(&self, context: &ProviderContext, target: &InvestigationTarget) -> SpectreResult<Vec<FindingDraft>> {
        let InvestigationTarget::Username(username) = target else { return Ok(Vec::new()) };
        let mut url = endpoint(&self.base, &["api", "users", "by_username"]);
        url.query_pairs_mut().append_pair("url", username);
        let response = context.get(context.request(url.clone())).await?;
        if response.status == 404 {
            return Ok(Vec::new());
        }
        let user: DevToUser = response.ensure_success()?.json()?;
        let mut linked_accounts = Vec::new();
        if let Some(handle) = non_empty(user.github_username.as_deref()) {
            linked_accounts.push(handle_link("GitHub", &handle, format!("https://github.com/{handle}")));
        }
        if let Some(handle) = non_empty(user.twitter_username.as_deref()) {
            linked_accounts.push(handle_link("X", &handle, format!("https://x.com/{handle}")));
        }
        let website = user.website_url.as_deref().and_then(normalize_link);
        if let Some(site) = &website {
            linked_accounts.push(link(site.clone()));
        }
        let profile = ProfileFinding {
            platform: "DEV Community".to_string(),
            username: user.username.clone(),
            profile_url: format!("https://dev.to/{}", user.username),
            display_name: non_empty(user.name.as_deref()),
            bio: non_empty(user.summary.as_deref()),
            avatar_url: user.profile_image,
            website,
            location: non_empty(user.location.as_deref()),
            account_created_at: user.joined_at,
            linked_accounts,
            ..Default::default()
        };
        Ok(vec![profile_draft(context, profile, &url)])
    }
}

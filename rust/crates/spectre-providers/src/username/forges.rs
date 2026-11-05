//! Source-code forges: GitHub, GitLab, Codeberg.

use async_trait::async_trait;
use serde::Deserialize;
use spectre_core::credentials::ids;
use spectre_core::error::{ErrorCode, SpectreError, SpectreResult};
use spectre_core::model::ProfileFinding;
use spectre_core::provider::{CredentialRequirement, FindingDraft, OsintProvider, ProviderCapability, ProviderContext};
use spectre_core::target::{InvestigationTarget, TargetType};
use url::Url;

use crate::common::{
    attributes, base_url, endpoint, handle_link, host_of, link, non_empty, normalize_link, profile_draft, public_email_draft,
};
use crate::provider_metadata;

// ---------------------------------------------------------------------------
// GitHub — https://docs.github.com/rest/users/users#get-a-user
// ---------------------------------------------------------------------------

pub struct GitHubProvider {
    base: Url,
}

impl Default for GitHubProvider {
    fn default() -> Self {
        Self { base: base_url("https://api.github.com/") }
    }
}

impl GitHubProvider {
    pub fn with_base(base: Url) -> Self {
        Self { base }
    }
}

#[derive(Deserialize)]
struct GitHubUser {
    login: String,
    html_url: String,
    name: Option<String>,
    bio: Option<String>,
    avatar_url: Option<String>,
    blog: Option<String>,
    location: Option<String>,
    email: Option<String>,
    twitter_username: Option<String>,
    company: Option<String>,
    public_repos: Option<u64>,
    followers: Option<u64>,
    created_at: Option<String>,
    #[serde(rename = "type")]
    account_type: Option<String>,
}

#[derive(Deserialize)]
struct GitHubSocialAccount {
    provider: String,
    url: String,
}

#[async_trait]
impl OsintProvider for GitHubProvider {
    provider_metadata! {
        id: "github",
        name: "GitHub",
        description: "Public GitHub user profiles and linked social accounts via the REST API.",
        homepage: "https://github.com",
        targets: [TargetType::Username],
        capabilities: [ProviderCapability::ProfileLookup, ProviderCapability::LinkedAccounts, ProviderCapability::PublicEmailAssociation],
    }

    fn allowed_hosts(&self) -> Vec<String> {
        vec![host_of(&self.base)]
    }

    fn credential_requirement(&self) -> CredentialRequirement {
        CredentialRequirement::Optional {
            credential_id: ids::GITHUB_TOKEN.to_string(),
            purpose: "Raises the unauthenticated limit of 60 requests/hour. A token with no scopes is sufficient.".to_string(),
        }
    }

    async fn discover(&self, context: &ProviderContext, target: &InvestigationTarget) -> SpectreResult<Vec<FindingDraft>> {
        let InvestigationTarget::Username(username) = target else { return Ok(Vec::new()) };
        let token = context.credentials.get(ids::GITHUB_TOKEN);
        let build = |url: Url| -> SpectreResult<spectre_core::http::HttpRequest> {
            let mut request = context.request(url).accept("application/vnd.github+json").header("x-github-api-version", "2022-11-28")?;
            if let Some(token) = &token {
                request = request.sensitive_header("authorization", &format!("Bearer {}", token.as_str()))?;
            }
            Ok(request)
        };

        let user_url = endpoint(&self.base, &["users", username]);
        let response = context.get(build(user_url.clone())?).await?;
        if response.status == 404 {
            return Ok(Vec::new());
        }
        if response.status == 403 && response.text().to_ascii_lowercase().contains("rate limit") {
            return Err(SpectreError::new(
                ErrorCode::RateLimited,
                "GitHub API rate limit reached. Add a GitHub token in Settings → Providers to raise the limit.",
            ));
        }
        let user: GitHubUser = response.ensure_success()?.json()?;

        let mut linked_accounts = Vec::new();
        if let Some(blog) = user.blog.as_deref().and_then(normalize_link) {
            linked_accounts.push(link(blog));
        }
        if let Some(handle) = non_empty(user.twitter_username.as_deref()) {
            linked_accounts.push(handle_link("X", &handle, format!("https://x.com/{handle}")));
        }
        let mut social_note = None;
        let social_url = endpoint(&self.base, &["users", &user.login, "social_accounts"]);
        match context.get(build(social_url)?).await.and_then(|response| response.ensure_success()) {
            Ok(response) => {
                for account in response.json::<Vec<GitHubSocialAccount>>().unwrap_or_default() {
                    if let Some(url) = normalize_link(&account.url)
                        && !linked_accounts.iter().any(|existing| existing.url.as_deref() == Some(url.as_str()))
                    {
                        linked_accounts.push(spectre_core::model::LinkedAccount {
                            platform: Some(account.provider),
                            url: Some(url),
                            ..Default::default()
                        });
                    }
                }
            }
            Err(error) if error.code == ErrorCode::Cancelled => return Err(error),
            Err(error) => social_note = Some(format!("social accounts unavailable: {}", error.message)),
        }

        let profile = ProfileFinding {
            platform: "GitHub".to_string(),
            username: user.login.clone(),
            profile_url: user.html_url.clone(),
            display_name: non_empty(user.name.as_deref()),
            bio: non_empty(user.bio.as_deref()),
            avatar_url: user.avatar_url.clone(),
            website: user.blog.as_deref().and_then(normalize_link),
            location: non_empty(user.location.as_deref()),
            account_created_at: user.created_at.clone(),
            platform_verified: false,
            public_email: non_empty(user.email.as_deref()),
            linked_accounts,
            attributes: attributes([
                ("account_type", user.account_type.clone()),
                ("company", non_empty(user.company.as_deref())),
                ("public_repositories", user.public_repos.map(|count| count.to_string())),
                ("followers", user.followers.map(|count| count.to_string())),
                ("note", social_note),
            ]),
        };
        let mut drafts = Vec::new();
        if let Some(email) = &profile.public_email {
            drafts.extend(public_email_draft(context, "GitHub", email, &profile.profile_url));
        }
        drafts.insert(0, profile_draft(context, profile, &user_url));
        Ok(drafts)
    }
}

// ---------------------------------------------------------------------------
// GitLab — https://docs.gitlab.com/api/users/#list-users
// ---------------------------------------------------------------------------

pub struct GitLabProvider {
    base: Url,
}

impl Default for GitLabProvider {
    fn default() -> Self {
        Self { base: base_url("https://gitlab.com/") }
    }
}

impl GitLabProvider {
    pub fn with_base(base: Url) -> Self {
        Self { base }
    }
}

#[derive(Deserialize)]
struct GitLabUser {
    username: String,
    name: Option<String>,
    state: Option<String>,
    avatar_url: Option<String>,
    web_url: String,
    public_email: Option<String>,
}

#[async_trait]
impl OsintProvider for GitLabProvider {
    provider_metadata! {
        id: "gitlab",
        name: "GitLab",
        description: "Public GitLab.com user accounts via the users API.",
        homepage: "https://gitlab.com",
        targets: [TargetType::Username],
        capabilities: [ProviderCapability::ProfileLookup, ProviderCapability::PublicEmailAssociation],
    }

    fn allowed_hosts(&self) -> Vec<String> {
        vec![host_of(&self.base)]
    }

    async fn discover(&self, context: &ProviderContext, target: &InvestigationTarget) -> SpectreResult<Vec<FindingDraft>> {
        let InvestigationTarget::Username(username) = target else { return Ok(Vec::new()) };
        let mut url = endpoint(&self.base, &["api", "v4", "users"]);
        url.query_pairs_mut().append_pair("username", username);
        let users: Vec<GitLabUser> = context.get(context.request(url.clone())).await?.ensure_success()?.json()?;
        let Some(user) = users.into_iter().next() else { return Ok(Vec::new()) };
        let profile = ProfileFinding {
            platform: "GitLab".to_string(),
            username: user.username,
            profile_url: user.web_url,
            display_name: non_empty(user.name.as_deref()),
            avatar_url: user.avatar_url,
            public_email: non_empty(user.public_email.as_deref()),
            attributes: attributes([("state", user.state)]),
            ..Default::default()
        };
        let mut drafts = Vec::new();
        if let Some(email) = &profile.public_email {
            drafts.extend(public_email_draft(context, "GitLab", email, &profile.profile_url));
        }
        drafts.insert(0, profile_draft(context, profile, &url));
        Ok(drafts)
    }
}

// ---------------------------------------------------------------------------
// Codeberg (Forgejo) — https://codeberg.org/api/swagger#/user/userGet
// ---------------------------------------------------------------------------

pub struct CodebergProvider {
    base: Url,
}

impl Default for CodebergProvider {
    fn default() -> Self {
        Self { base: base_url("https://codeberg.org/") }
    }
}

impl CodebergProvider {
    pub fn with_base(base: Url) -> Self {
        Self { base }
    }
}

#[derive(Deserialize)]
struct CodebergUser {
    login: String,
    full_name: Option<String>,
    avatar_url: Option<String>,
    html_url: String,
    created: Option<String>,
    location: Option<String>,
    website: Option<String>,
    description: Option<String>,
    email: Option<String>,
    followers_count: Option<u64>,
}

#[async_trait]
impl OsintProvider for CodebergProvider {
    provider_metadata! {
        id: "codeberg",
        name: "Codeberg",
        description: "Public Codeberg (Forgejo) user profiles via the REST API.",
        homepage: "https://codeberg.org",
        targets: [TargetType::Username],
        capabilities: [ProviderCapability::ProfileLookup, ProviderCapability::LinkedAccounts],
    }

    fn allowed_hosts(&self) -> Vec<String> {
        vec![host_of(&self.base)]
    }

    async fn discover(&self, context: &ProviderContext, target: &InvestigationTarget) -> SpectreResult<Vec<FindingDraft>> {
        let InvestigationTarget::Username(username) = target else { return Ok(Vec::new()) };
        let url = endpoint(&self.base, &["api", "v1", "users", username]);
        let response = context.get(context.request(url.clone())).await?;
        if response.status == 404 {
            return Ok(Vec::new());
        }
        let user: CodebergUser = response.ensure_success()?.json()?;
        let website = user.website.as_deref().and_then(normalize_link);
        let profile = ProfileFinding {
            platform: "Codeberg".to_string(),
            username: user.login,
            profile_url: user.html_url,
            display_name: non_empty(user.full_name.as_deref()),
            bio: non_empty(user.description.as_deref()),
            avatar_url: user.avatar_url,
            website: website.clone(),
            location: non_empty(user.location.as_deref()),
            account_created_at: user.created,
            public_email: non_empty(user.email.as_deref()).filter(|email| !email.contains("noreply")),
            linked_accounts: website.into_iter().map(link).collect(),
            attributes: attributes([("followers", user.followers_count.map(|count| count.to_string()))]),
            ..Default::default()
        };
        let mut drafts = Vec::new();
        if let Some(email) = &profile.public_email {
            drafts.extend(public_email_draft(context, "Codeberg", email, &profile.profile_url));
        }
        drafts.insert(0, profile_draft(context, profile, &url));
        Ok(drafts)
    }
}

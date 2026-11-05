//! Have I Been Pwned API v3: https://haveibeenpwned.com/API/v3

use async_trait::async_trait;
use scraper::Html;
use serde::Deserialize;
use spectre_core::credentials::ids;
use spectre_core::error::{ErrorCode, SpectreError, SpectreResult};
use spectre_core::model::BreachIncident;
use spectre_core::provider::ProviderContext;
use url::Url;

use crate::{AuthorizedAccount, BreachProvider};

pub const HIBP_HOST: &str = "haveibeenpwned.com";
pub const HIBP_ATTRIBUTION: &str = "Have I Been Pwned (haveibeenpwned.com), licensed under CC BY 4.0";

/// Breach model as returned by the API (PascalCase fields).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct HibpBreach {
    pub name: String,
    pub title: String,
    pub domain: Option<String>,
    pub breach_date: Option<String>,
    pub added_date: Option<String>,
    pub modified_date: Option<String>,
    #[serde(default)]
    pub pwn_count: u64,
    #[serde(default)]
    pub description: String,
    pub logo_path: Option<String>,
    #[serde(default)]
    pub data_classes: Vec<String>,
    #[serde(default)]
    pub is_verified: bool,
    #[serde(default)]
    pub is_fabricated: bool,
    #[serde(default)]
    pub is_sensitive: bool,
    #[serde(default)]
    pub is_retired: bool,
    #[serde(default)]
    pub is_spam_list: bool,
    #[serde(default)]
    pub is_malware: bool,
    #[serde(default)]
    pub is_stealer_log: bool,
}

/// Data classes that indicate password material was part of the breach.
const PASSWORD_CLASSES: [&str; 3] = ["passwords", "historical passwords", "password hints"];

impl From<HibpBreach> for BreachIncident {
    fn from(breach: HibpBreach) -> Self {
        let password_data_exposed =
            breach.data_classes.iter().any(|class| PASSWORD_CLASSES[..2].contains(&class.to_ascii_lowercase().as_str()));
        BreachIncident {
            name: breach.name,
            title: breach.title,
            domain: breach.domain.filter(|domain| !domain.is_empty()),
            breach_date: breach.breach_date,
            added_date: breach.added_date,
            modified_date: breach.modified_date,
            pwn_count: breach.pwn_count,
            description: strip_description(&breach.description),
            data_classes: breach.data_classes,
            password_data_exposed,
            is_verified: breach.is_verified,
            is_fabricated: breach.is_fabricated,
            is_sensitive: breach.is_sensitive,
            is_retired: breach.is_retired,
            is_spam_list: breach.is_spam_list,
            is_malware: breach.is_malware,
            is_stealer_log: breach.is_stealer_log,
            logo_url: breach.logo_path,
            source: "Have I Been Pwned".to_string(),
        }
    }
}

/// HIBP descriptions contain HTML; reduce them to plain text.
pub fn strip_description(html: &str) -> String {
    let fragment = Html::parse_fragment(html);
    let text: String = fragment.root_element().text().collect::<Vec<_>>().join("");
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub struct HibpClient {
    base: Url,
}

impl Default for HibpClient {
    fn default() -> Self {
        Self { base: Url::parse("https://haveibeenpwned.com/api/v3/").expect("valid URL") }
    }
}

impl HibpClient {
    pub fn with_base(base: Url) -> Self {
        Self { base }
    }

    fn url(&self, segments: &[&str]) -> Url {
        let mut url = self.base.clone();
        if let Ok(mut path) = url.path_segments_mut() {
            path.pop_if_empty();
            for segment in segments {
                path.push(segment);
            }
        }
        url
    }

    fn map_status(status: u16, url: &Url, retry_after: Option<std::time::Duration>) -> SpectreError {
        match status {
            401 => SpectreError::new(
                ErrorCode::Unauthorized,
                "Have I Been Pwned rejected the API key (401). Check the key in Settings > Providers.",
            ),
            403 => SpectreError::new(
                ErrorCode::Unauthorized,
                "Have I Been Pwned denied the request (403). The key's plan may not include this endpoint.",
            ),
            other => spectre_core::http::status_error(other, url, retry_after),
        }
    }
}

#[async_trait]
impl BreachProvider for HibpClient {
    fn id(&self) -> &str {
        "hibp"
    }

    fn name(&self) -> &str {
        "Have I Been Pwned"
    }

    fn allowed_hosts(&self) -> Vec<String> {
        vec![self.base.host_str().unwrap_or(HIBP_HOST).to_string()]
    }

    fn attribution(&self) -> &str {
        HIBP_ATTRIBUTION
    }

    async fn account_breaches(&self, context: &ProviderContext, account: &AuthorizedAccount) -> SpectreResult<Vec<BreachIncident>> {
        let key = context.credentials.get(ids::HIBP_API_KEY).ok_or_else(|| {
            SpectreError::credentials_missing(
                "Account breach lookups need a Have I Been Pwned API key. Add one in Settings > Providers (https://haveibeenpwned.com/API/Key).",
            )
        })?;
        let mut url = self.url(&["breachedaccount", account.email()]);
        url.query_pairs_mut().append_pair("truncateResponse", "false");
        let request = context.request(url.clone()).no_cache().sensitive_header("hibp-api-key", key.as_str())?;
        let response = context.get(request).await?;
        match response.status {
            200 => Ok(response.json::<Vec<HibpBreach>>()?.into_iter().map(BreachIncident::from).collect()),
            404 => Ok(Vec::new()),
            status => Err(Self::map_status(status, &url, response.retry_after)),
        }
    }

    async fn catalog(&self, context: &ProviderContext, domain: Option<&str>) -> SpectreResult<Vec<BreachIncident>> {
        let mut url = self.url(&["breaches"]);
        if let Some(domain) = domain {
            url.query_pairs_mut().append_pair("Domain", domain);
        }
        let response = context.get(context.request(url.clone())).await?;
        if !response.is_success() {
            return Err(Self::map_status(response.status, &url, response.retry_after));
        }
        Ok(response.json::<Vec<HibpBreach>>()?.into_iter().map(BreachIncident::from).collect())
    }
}

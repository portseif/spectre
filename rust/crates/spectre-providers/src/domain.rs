//! Domain intelligence: DNS configuration, RDAP registration data, and the
//! domain's public website (homepage metadata, `rel="me"` links, security.txt).

use std::collections::BTreeSet;

use async_trait::async_trait;
use scraper::{Html, Selector};
use serde::Deserialize;
use spectre_core::error::{ErrorCode, SpectreError, SpectreResult};
use spectre_core::model::{
    CertificateFinding, DiscoveryMethod, DnsRecord, DnsRecordsFinding, DomainRegistrationFinding, FindingData, HeaderCheck, SecurityTxt,
    VerificationStatus, WebArchiveFinding, WebPresenceFinding,
};
use spectre_core::provider::{CredentialRequirement, FindingDraft, OsintProvider, ProviderCapability, ProviderContext};
use spectre_core::target::{InvestigationTarget, TargetType};
use url::Url;

use crate::common::{base_url, endpoint, host_of, normalize_link, observed_fact, truncate};
use crate::dns::{DohResolver, RecordType, ResponseCode, find_dmarc, find_spf};
use crate::provider_metadata;

// ---------------------------------------------------------------------------
// DNS records
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct DomainDnsProvider {
    resolver: DohResolver,
}

impl DomainDnsProvider {
    pub fn with_resolver(resolver: DohResolver) -> Self {
        Self { resolver }
    }
}

/// Security observations derived from DNS configuration.
pub fn dns_observations(records: &[DnsRecord], spf: Option<&str>, dmarc: Option<&str>) -> Vec<String> {
    let mut observations = Vec::new();
    let has = |record_type: &str| records.iter().any(|record| record.record_type == record_type);
    match spf {
        None if has("MX") => observations.push("No SPF record: other servers can send mail claiming to be this domain".to_string()),
        Some(policy) if policy.contains("+all") => {
            observations.push("SPF policy ends in +all, which authorizes every server to send mail for the domain".to_string());
        }
        Some(policy) if policy.contains("?all") => observations.push("SPF policy is neutral (?all) and provides no protection".to_string()),
        _ => {}
    }
    match dmarc.map(str::to_ascii_lowercase) {
        None => observations.push("No DMARC policy published at _dmarc".to_string()),
        Some(policy) if policy.replace(' ', "").contains("p=none") => {
            observations.push("DMARC policy is p=none (monitoring only; spoofed mail is not rejected)".to_string());
        }
        _ => {}
    }
    if !has("CAA") {
        observations.push("No CAA record: any certificate authority may issue certificates for the domain".to_string());
    }
    observations
}

#[async_trait]
impl OsintProvider for DomainDnsProvider {
    provider_metadata! {
        id: "domain-dns",
        name: "DNS Records",
        description: "A, AAAA, MX, NS, TXT, and CAA records plus SPF/DMARC posture over DNS-over-HTTPS.",
        homepage: "https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/",
        targets: [TargetType::Domain],
        capabilities: [ProviderCapability::DnsRecords],
    }

    fn allowed_hosts(&self) -> Vec<String> {
        vec![self.resolver.host()]
    }

    fn default_rate_limit_per_minute(&self) -> u32 {
        120
    }

    async fn discover(&self, context: &ProviderContext, target: &InvestigationTarget) -> SpectreResult<Vec<FindingDraft>> {
        let InvestigationTarget::Domain(domain) = target else { return Ok(Vec::new()) };
        let mut records = Vec::new();
        for record_type in [RecordType::A, RecordType::Aaaa, RecordType::Mx, RecordType::Ns, RecordType::Txt, RecordType::Caa] {
            let answer = self.resolver.query(context, domain, record_type).await?;
            if answer.response_code == ResponseCode::NxDomain {
                return Err(SpectreError::not_found(format!("{domain} does not exist in DNS (NXDOMAIN)")));
            }
            records.extend(answer.records);
        }
        let txt_values: Vec<String> =
            records.iter().filter(|record| record.record_type == "TXT").map(|record| record.value.clone()).collect();
        let dmarc_values = self.resolver.txt(context, &format!("_dmarc.{domain}")).await?;
        let spf = find_spf(&txt_values);
        let dmarc = find_dmarc(&dmarc_values);
        let observations = dns_observations(&records, spf.as_deref(), dmarc.as_deref());
        Ok(vec![FindingDraft {
            title: format!("DNS records for {domain}"),
            summary: Some(format!("{} record(s); {} observation(s)", records.len(), observations.len())),
            confidence: observed_fact("Directly observed in public DNS"),
            verification_status: VerificationStatus::PubliclyObserved,
            sources: vec![context.source(Some(format!("dns:{domain}")), DiscoveryMethod::DnsQuery)],
            data: FindingData::DnsRecords(DnsRecordsFinding { domain: domain.clone(), records, spf, dmarc, observations }),
        }])
    }
}

// ---------------------------------------------------------------------------
// RDAP (RFC 9082/9083), bootstrap per RFC 9224
// ---------------------------------------------------------------------------

pub struct RdapProvider {
    bootstrap: Url,
}

impl Default for RdapProvider {
    fn default() -> Self {
        Self { bootstrap: base_url("https://data.iana.org/rdap/dns.json") }
    }
}

impl RdapProvider {
    pub fn with_bootstrap(bootstrap: Url) -> Self {
        Self { bootstrap }
    }
}

#[derive(Deserialize)]
struct RdapBootstrap {
    services: Vec<(Vec<String>, Vec<String>)>,
}

/// Pick the HTTPS RDAP base URL for a TLD from the IANA bootstrap registry.
fn rdap_base_for(bootstrap: &RdapBootstrap, top_level: &str, allow_loopback: bool) -> Option<Url> {
    bootstrap.services.iter().find(|(tlds, _)| tlds.iter().any(|tld| tld.eq_ignore_ascii_case(top_level))).and_then(|(_, urls)| {
        urls.iter().filter_map(|raw| Url::parse(raw).ok()).find(|url| url.scheme() == "https" || (allow_loopback && url.scheme() == "http"))
    })
}

/// Parse an RDAP domain object into a registration finding.
pub fn parse_rdap_domain(domain: &str, rdap_url: &Url, document: &serde_json::Value) -> DomainRegistrationFinding {
    let event = |action: &str| {
        document["events"]
            .as_array()
            .and_then(|events| events.iter().find(|event| event["eventAction"].as_str() == Some(action)))
            .and_then(|event| event["eventDate"].as_str())
            .map(str::to_string)
    };
    let registrar = document["entities"].as_array().and_then(|entities| {
        entities
            .iter()
            .find(|entity| entity["roles"].as_array().is_some_and(|roles| roles.iter().any(|role| role.as_str() == Some("registrar"))))
            .and_then(|entity| entity["vcardArray"][1].as_array())
            .and_then(|properties| properties.iter().find(|property| property[0].as_str() == Some("fn")))
            .and_then(|property| property[3].as_str())
            .map(str::to_string)
    });
    let statuses = document["status"]
        .as_array()
        .map(|values| values.iter().filter_map(|value| value.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let nameservers = document["nameservers"]
        .as_array()
        .map(|values| values.iter().filter_map(|value| value["ldhName"].as_str().map(str::to_ascii_lowercase)).collect())
        .unwrap_or_default();
    DomainRegistrationFinding {
        domain: domain.to_string(),
        registrar,
        registered_at: event("registration"),
        expires_at: event("expiration"),
        last_changed_at: event("last changed"),
        statuses,
        nameservers,
        dnssec_signed: document["secureDNS"]["delegationSigned"].as_bool(),
        rdap_url: rdap_url.to_string(),
    }
}

#[async_trait]
impl OsintProvider for RdapProvider {
    provider_metadata! {
        id: "rdap",
        name: "RDAP Registration",
        description: "Registrar, lifecycle dates, status, and nameservers from the registry's RDAP service (IANA bootstrap).",
        homepage: "https://www.iana.org/domains/rdap",
        targets: [TargetType::Domain],
        capabilities: [ProviderCapability::DomainRegistration],
    }

    fn allowed_hosts(&self) -> Vec<String> {
        // Registry RDAP hosts are added at runtime from the IANA bootstrap file.
        vec![host_of(&self.bootstrap)]
    }

    async fn discover(&self, context: &ProviderContext, target: &InvestigationTarget) -> SpectreResult<Vec<FindingDraft>> {
        let InvestigationTarget::Domain(domain) = target else { return Ok(Vec::new()) };
        let bootstrap: RdapBootstrap = context.get(context.request(self.bootstrap.clone())).await?.ensure_success()?.json()?;
        let top_level = domain.rsplit('.').next().unwrap_or_default();
        let allow_loopback = self.bootstrap.scheme() == "http";
        let base = rdap_base_for(&bootstrap, top_level, allow_loopback)
            .ok_or_else(|| SpectreError::not_found(format!("no RDAP service is registered for .{top_level}")))?;
        // The registry endpoint comes from IANA's authoritative bootstrap registry.
        context.http.policy().allow_host(host_of(&base));

        // Registries answer for registered names only; walk up from subdomains.
        let labels: Vec<&str> = domain.split('.').collect();
        for start in 0..labels.len().saturating_sub(1).min(3) {
            let candidate = labels[start..].join(".");
            let url = endpoint(&base, &["domain", &candidate]);
            let response = context.get(context.request(url.clone()).accept("application/rdap+json")).await?;
            if response.status == 404 {
                continue;
            }
            let document: serde_json::Value = response.ensure_success()?.json()?;
            let registration = parse_rdap_domain(&candidate, &url, &document);
            let summary = registration
                .registrar
                .as_ref()
                .map(|registrar| format!("Registrar: {registrar}"))
                .or_else(|| registration.registered_at.as_ref().map(|date| format!("Registered {date}")));
            return Ok(vec![FindingDraft {
                title: format!("Registration of {candidate}"),
                summary,
                confidence: observed_fact("Reported by the authoritative registry's RDAP service"),
                verification_status: VerificationStatus::PubliclyObserved,
                sources: vec![context.source(Some(url.to_string()), DiscoveryMethod::RdapQuery)],
                data: FindingData::DomainRegistration(registration),
            }]);
        }
        Ok(Vec::new())
    }
}

// ---------------------------------------------------------------------------
// Public website
// ---------------------------------------------------------------------------

/// Hosts whose links on a homepage are reported as profile links.
const PROFILE_HOSTS: [&str; 16] = [
    "github.com",
    "gitlab.com",
    "codeberg.org",
    "x.com",
    "twitter.com",
    "linkedin.com",
    "mastodon.social",
    "bsky.app",
    "keybase.io",
    "facebook.com",
    "instagram.com",
    "youtube.com",
    "threads.net",
    "huggingface.co",
    "dev.to",
    "news.ycombinator.com",
];

pub struct WebsiteProvider;

#[derive(Debug, Default, PartialEq)]
pub struct HomepageMetadata {
    pub title: Option<String>,
    pub description: Option<String>,
    pub rel_me_links: Vec<String>,
    pub profile_links: Vec<String>,
}

/// Extract identity-relevant metadata from a homepage (sync: `Html` is not `Send`).
pub fn parse_homepage(html: &str, page_url: &Url) -> HomepageMetadata {
    let document = Html::parse_document(html);
    let select = |css: &str| Selector::parse(css).expect("valid selector");
    let title = document
        .select(&select("title"))
        .next()
        .map(|element| element.text().collect::<String>().split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|text| !text.is_empty())
        .map(|text| truncate(&text, 200));
    let description = document
        .select(&select(r#"meta[name="description"], meta[property="og:description"]"#))
        .find_map(|element| element.value().attr("content"))
        .map(|content| truncate(content.trim(), 300))
        .filter(|text| !text.is_empty());

    let resolve = |href: &str| page_url.join(href).ok().filter(|url| matches!(url.scheme(), "http" | "https")).map(|url| url.to_string());
    let mut rel_me = BTreeSet::new();
    for element in document.select(&select("a[rel][href], link[rel][href]")) {
        let is_me = element.value().attr("rel").is_some_and(|rel| rel.split_whitespace().any(|token| token.eq_ignore_ascii_case("me")));
        if let (true, Some(href)) = (is_me, element.value().attr("href").and_then(resolve)) {
            rel_me.insert(href);
        }
    }
    let mut profile_links = BTreeSet::new();
    for href in document.select(&select("a[href]")).filter_map(|element| element.value().attr("href")).filter_map(resolve) {
        let Ok(url) = Url::parse(&href) else { continue };
        let host = url.host_str().unwrap_or_default().trim_start_matches("www.").to_ascii_lowercase();
        let site_host = page_url.host_str().unwrap_or_default().trim_start_matches("www.").to_ascii_lowercase();
        let is_self_link = host == site_host || host.ends_with(&format!(".{site_host}"));
        if !is_self_link && PROFILE_HOSTS.contains(&host.as_str()) && url.path().trim_matches('/').len() > 1 {
            profile_links.insert(href);
        }
    }
    HomepageMetadata {
        title,
        description,
        rel_me_links: rel_me.into_iter().take(50).collect(),
        profile_links: profile_links.into_iter().take(20).collect(),
    }
}

/// Passive review of the homepage's security headers. Nothing is probed:
/// this only reads the response the site already sent.
pub fn review_security_headers(headers: &[(String, String)]) -> (Option<String>, Vec<HeaderCheck>) {
    let get = |name: &str| headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.clone());
    let csp = get("content-security-policy");
    let mut checks = Vec::new();

    let hsts = get("strict-transport-security");
    let hsts_note = match &hsts {
        None => Some("Missing. Browsers may try plain HTTP before being redirected.".to_string()),
        Some(value) => {
            let max_age = value
                .split(';')
                .find_map(|part| part.trim().strip_prefix("max-age=").and_then(|age| age.trim_matches('"').parse::<u64>().ok()));
            match max_age {
                Some(age) if age < 15_552_000 => Some(format!("max-age is {age}s; six months (15552000) or more is usual.")),
                None => Some("No max-age directive.".to_string()),
                _ => None,
            }
        }
    };
    checks.push(HeaderCheck { header: "Strict-Transport-Security".into(), present: hsts.is_some(), value: hsts, note: hsts_note });

    checks.push(HeaderCheck {
        header: "Content-Security-Policy".into(),
        present: csp.is_some(),
        note: csp.is_none().then(|| "Missing. A policy limits the damage from injected scripts.".to_string()),
        value: csp.clone(),
    });

    let nosniff = get("x-content-type-options");
    let nosniff_ok = nosniff.as_deref().is_some_and(|value| value.trim().eq_ignore_ascii_case("nosniff"));
    checks.push(HeaderCheck {
        header: "X-Content-Type-Options".into(),
        present: nosniff.is_some(),
        note: (!nosniff_ok).then(|| "Should be \"nosniff\" so browsers don't guess content types.".to_string()),
        value: nosniff,
    });

    let frame_options = get("x-frame-options");
    let frame_ancestors = csp.as_deref().is_some_and(|policy| policy.to_ascii_lowercase().contains("frame-ancestors"));
    checks.push(HeaderCheck {
        header: "X-Frame-Options / frame-ancestors".into(),
        present: frame_options.is_some() || frame_ancestors,
        note: (frame_options.is_none() && !frame_ancestors).then(|| "Missing. Other sites can frame this page (clickjacking).".to_string()),
        value: frame_options.or_else(|| frame_ancestors.then(|| "set in Content-Security-Policy".to_string())),
    });

    let referrer = get("referrer-policy");
    checks.push(HeaderCheck {
        header: "Referrer-Policy".into(),
        present: referrer.is_some(),
        note: referrer.is_none().then(|| "Not set; browsers fall back to their default policy.".to_string()),
        value: referrer,
    });

    let banner = [get("server"), get("x-powered-by")].into_iter().flatten().collect::<Vec<_>>().join(", ");
    let banner = (!banner.is_empty()).then_some(banner);
    if let Some(value) = &banner
        && value.chars().any(|character| character.is_ascii_digit())
    {
        checks.push(HeaderCheck {
            header: "Server banner".into(),
            present: true,
            value: Some(value.clone()),
            note: Some("Discloses software versions, which helps attackers match known vulnerabilities.".into()),
        });
    }
    (banner, checks)
}

/// Parse an RFC 9116 security.txt file.
pub fn parse_security_txt(url: &str, body: &str) -> Option<SecurityTxt> {
    let mut parsed = SecurityTxt { url: url.to_string(), contacts: Vec::new(), policy: None, expires: None, encryption: None };
    for line in body.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some((field, value)) = line.split_once(':') else { continue };
        let value = value.trim().to_string();
        match field.trim().to_ascii_lowercase().as_str() {
            "contact" => parsed.contacts.push(value),
            "policy" => parsed.policy = Some(value),
            "expires" => parsed.expires = Some(value),
            "encryption" => parsed.encryption = Some(value),
            _ => {}
        }
    }
    (!parsed.contacts.is_empty()).then_some(parsed)
}

#[async_trait]
impl OsintProvider for WebsiteProvider {
    provider_metadata! {
        id: "website",
        name: "Public Website",
        description: "Fetches the domain's public homepage and security.txt (HTTPS only, public IPs only) for rel=\"me\" identity links and contacts.",
        homepage: "https://www.rfc-editor.org/rfc/rfc9116",
        targets: [TargetType::Domain],
        capabilities: [ProviderCapability::WebPresence, ProviderCapability::LinkedAccounts],
    }

    fn allowed_hosts(&self) -> Vec<String> {
        // Destinations are the investigated domain itself, validated per
        // request by `HttpClient::fetch_public_web` (public addresses only).
        Vec::new()
    }

    fn default_rate_limit_per_minute(&self) -> u32 {
        20
    }

    async fn discover(&self, context: &ProviderContext, target: &InvestigationTarget) -> SpectreResult<Vec<FindingDraft>> {
        let InvestigationTarget::Domain(domain) = target else { return Ok(Vec::new()) };
        let homepage_url =
            Url::parse(&format!("https://{domain}/")).map_err(|_| SpectreError::invalid_input("domain cannot be expressed as a URL"))?;
        let response =
            context.http.fetch_public_web(&context.provider_id, homepage_url.clone(), &context.cancellation, &context.stats).await?;
        if !(200..300).contains(&response.status) {
            return Err(SpectreError::new(ErrorCode::UpstreamError, format!("{domain} homepage returned HTTP {}", response.status)));
        }
        let metadata = parse_homepage(&response.text(), &response.final_url);
        let (server_banner, header_checks) = review_security_headers(&response.headers);

        let security_url = Url::parse(&format!("https://{domain}/.well-known/security.txt")).expect("valid URL");
        let security_txt =
            match context.http.fetch_public_web(&context.provider_id, security_url.clone(), &context.cancellation, &context.stats).await {
                Ok(security) if security.status == 200 => parse_security_txt(security.final_url.as_str(), &security.text()),
                Ok(_) => None,
                Err(error) if error.code == ErrorCode::Cancelled => return Err(error),
                Err(error) => {
                    tracing::debug!(provider = "website", code = ?error.code, "security.txt unavailable");
                    None
                }
            };

        let summary = metadata.title.clone().unwrap_or_else(|| format!("{} rel=\"me\" link(s)", metadata.rel_me_links.len()));
        let mut sources = vec![context.source(Some(response.final_url.to_string()), DiscoveryMethod::PublicWebPage)];
        if let Some(security) = &security_txt {
            sources.push(context.source(Some(security.url.clone()), DiscoveryMethod::PublicWebPage));
        }
        Ok(vec![FindingDraft {
            title: format!("Website of {domain}"),
            summary: Some(summary),
            confidence: observed_fact("Retrieved from the domain's public website"),
            verification_status: VerificationStatus::PubliclyObserved,
            sources,
            data: FindingData::WebPresence(WebPresenceFinding {
                url: response.final_url.to_string(),
                status_code: response.status,
                title: metadata.title,
                description: metadata.description,
                rel_me_links: metadata.rel_me_links.into_iter().filter_map(|href| normalize_link(&href)).collect(),
                profile_links: metadata.profile_links,
                security_txt,
                server_banner,
                header_checks,
            }),
        }])
    }
}

// ---------------------------------------------------------------------------
// Certificate Transparency (Cert Spotter): https://sslmate.com/help/reference/ct_search_api_v1
// ---------------------------------------------------------------------------

pub struct CertSpotterProvider {
    base: Url,
}

impl Default for CertSpotterProvider {
    fn default() -> Self {
        Self { base: base_url("https://api.certspotter.com/") }
    }
}

impl CertSpotterProvider {
    pub fn with_base(base: Url) -> Self {
        Self { base }
    }
}

#[derive(Deserialize)]
struct Issuance {
    #[serde(default)]
    dns_names: Vec<String>,
    issuer: Option<CertIssuer>,
    not_before: Option<String>,
    not_after: Option<String>,
    #[serde(default)]
    revoked: bool,
}

#[derive(Deserialize)]
struct CertIssuer {
    friendly_name: Option<String>,
    name: Option<String>,
}

const MAX_HOSTNAMES: usize = 500;

/// Summarize CT issuances for `domain`: hostnames under it, issuers, validity.
fn summarize_issuances(domain: &str, issuances: Vec<Issuance>, now: chrono::DateTime<chrono::Utc>) -> CertificateFinding {
    let suffix = format!(".{domain}");
    let mut hostnames = BTreeSet::new();
    let mut issuers = BTreeSet::new();
    let mut currently_valid = 0;
    let mut earliest: Option<String> = None;
    let mut latest: Option<String> = None;
    let certificates = issuances.len() as u32;
    for issuance in issuances {
        for name in &issuance.dns_names {
            let host = name.trim().trim_start_matches("*.").trim_end_matches('.').to_ascii_lowercase();
            if (host == domain || host.ends_with(&suffix)) && hostnames.len() < MAX_HOSTNAMES {
                hostnames.insert(host);
            }
        }
        if let Some(issuer) = issuance.issuer.and_then(|issuer| issuer.friendly_name.or(issuer.name)) {
            issuers.insert(issuer);
        }
        let valid = issuance
            .not_after
            .as_deref()
            .and_then(|date| chrono::DateTime::parse_from_rfc3339(date).ok())
            .is_some_and(|expiry| expiry > now);
        if valid && !issuance.revoked {
            currently_valid += 1;
        }
        if let Some(start) = issuance.not_before
            && earliest.as_ref().is_none_or(|current| &start < current)
        {
            earliest = Some(start);
        }
        if let Some(end) = issuance.not_after
            && latest.as_ref().is_none_or(|current| &end > current)
        {
            latest = Some(end);
        }
    }
    CertificateFinding {
        domain: domain.to_string(),
        hostnames: hostnames.into_iter().collect(),
        issuers: issuers.into_iter().collect(),
        certificates,
        currently_valid,
        earliest_not_before: earliest,
        latest_not_after: latest,
        source: "Cert Spotter (Certificate Transparency)".into(),
    }
}

#[async_trait]
impl OsintProvider for CertSpotterProvider {
    provider_metadata! {
        id: "certspotter",
        name: "Certificate Transparency",
        description: "Hostnames and issuers from certificates logged in public Certificate Transparency logs (via Cert Spotter).",
        homepage: "https://sslmate.com/certspotter/",
        targets: [TargetType::Domain],
        capabilities: [ProviderCapability::DnsRecords],
    }

    fn allowed_hosts(&self) -> Vec<String> {
        vec![host_of(&self.base)]
    }

    fn credential_requirement(&self) -> CredentialRequirement {
        CredentialRequirement::Optional {
            credential_id: spectre_core::credentials::ids::CERTSPOTTER_TOKEN.to_string(),
            purpose: "The free tier allows 10 lookups an hour. An SSLMate API key raises that.".to_string(),
        }
    }

    fn default_rate_limit_per_minute(&self) -> u32 {
        1
    }

    async fn discover(&self, context: &ProviderContext, target: &InvestigationTarget) -> SpectreResult<Vec<FindingDraft>> {
        let InvestigationTarget::Domain(domain) = target else { return Ok(Vec::new()) };
        let mut url = endpoint(&self.base, &["v1", "issuances"]);
        url.query_pairs_mut()
            .append_pair("domain", domain)
            .append_pair("include_subdomains", "true")
            .append_pair("expand", "dns_names")
            .append_pair("expand", "issuer");
        let mut request = context.request(url.clone());
        if let Some(token) = context.credentials.get(spectre_core::credentials::ids::CERTSPOTTER_TOKEN) {
            request = request.sensitive_header("authorization", &format!("Bearer {}", token.as_str()))?;
        }
        let response = context.get(request).await?;
        if response.status == 429 {
            return Err(SpectreError::new(
                ErrorCode::RateLimited,
                "Cert Spotter's free tier (10 lookups an hour) is used up. Try later or add an SSLMate key in Settings > Providers.",
            ));
        }
        let issuances: Vec<Issuance> = response.ensure_success()?.json()?;
        if issuances.is_empty() {
            return Ok(Vec::new());
        }
        let summary = summarize_issuances(domain, issuances, chrono::Utc::now());
        Ok(vec![FindingDraft {
            title: format!("Certificates for {domain}"),
            summary: Some(format!(
                "{} hostname(s) across {} certificate(s), {} currently valid",
                summary.hostnames.len(),
                summary.certificates,
                summary.currently_valid
            )),
            confidence: observed_fact("Logged in public Certificate Transparency logs"),
            verification_status: VerificationStatus::PubliclyObserved,
            sources: vec![context.source(Some(format!("https://sslmate.com/certspotter/?domain={domain}")), DiscoveryMethod::PublicApi)],
            data: FindingData::Certificates(summary),
        }])
    }
}

// ---------------------------------------------------------------------------
// Wayback Machine: https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server
// ---------------------------------------------------------------------------

pub struct WaybackProvider {
    base: Url,
}

impl Default for WaybackProvider {
    fn default() -> Self {
        Self { base: base_url("https://web.archive.org/") }
    }
}

impl WaybackProvider {
    pub fn with_base(base: Url) -> Self {
        Self { base }
    }

    async fn capture(&self, context: &ProviderContext, domain: &str, limit: &str) -> SpectreResult<Option<String>> {
        let mut url = endpoint(&self.base, &["cdx", "search", "cdx"]);
        url.query_pairs_mut()
            .append_pair("url", domain)
            .append_pair("output", "json")
            .append_pair("fl", "timestamp")
            .append_pair("limit", limit);
        let rows: Vec<Vec<String>> = context.get(context.request(url)).await?.ensure_success()?.json()?;
        Ok(rows.into_iter().nth(1).and_then(|row| row.into_iter().next()).and_then(|stamp| wayback_timestamp(&stamp)))
    }
}

/// `20080514210148` becomes `2008-05-14T21:01:48Z`.
pub fn wayback_timestamp(stamp: &str) -> Option<String> {
    let parsed = chrono::NaiveDateTime::parse_from_str(stamp, "%Y%m%d%H%M%S").ok()?;
    Some(parsed.and_utc().to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

#[async_trait]
impl OsintProvider for WaybackProvider {
    provider_metadata! {
        id: "wayback",
        name: "Wayback Machine",
        description: "First and latest Internet Archive captures of the domain's homepage.",
        homepage: "https://web.archive.org",
        targets: [TargetType::Domain],
        capabilities: [ProviderCapability::WebPresence],
    }

    fn allowed_hosts(&self) -> Vec<String> {
        vec![host_of(&self.base)]
    }

    fn default_rate_limit_per_minute(&self) -> u32 {
        15
    }

    async fn discover(&self, context: &ProviderContext, target: &InvestigationTarget) -> SpectreResult<Vec<FindingDraft>> {
        let InvestigationTarget::Domain(domain) = target else { return Ok(Vec::new()) };
        let Some(first) = self.capture(context, domain, "1").await? else { return Ok(Vec::new()) };
        let last = self.capture(context, domain, "-1").await?.unwrap_or_else(|| first.clone());
        let archive_url = format!("https://web.archive.org/web/*/{domain}");
        Ok(vec![FindingDraft {
            title: format!("Archive history of {domain}"),
            summary: Some(format!("Captured from {} to {}", &first[..10], &last[..10])),
            confidence: observed_fact("Recorded by the Internet Archive"),
            verification_status: VerificationStatus::PubliclyObserved,
            sources: vec![context.source(Some(archive_url.clone()), DiscoveryMethod::PublicApi)],
            data: FindingData::WebArchive(WebArchiveFinding { url: domain.clone(), first_capture: first, last_capture: last, archive_url }),
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn homepage_parsing_extracts_identity_links() {
        let html = r#"<html><head><title> Jane Doe </title>
            <meta name="description" content="Engineer">
            <link rel="me" href="https://mastodon.social/@jane"></head>
            <body><a rel="me noopener" href="https://github.com/janedoe">GitHub</a>
            <a href="https://x.com/janedoe">X</a><a href="/about">About</a>
            <a href="https://github.com/">root</a></body></html>"#;
        let metadata = parse_homepage(html, &Url::parse("https://jane.example.org/").unwrap());
        assert_eq!(metadata.title.as_deref(), Some("Jane Doe"));
        assert_eq!(metadata.description.as_deref(), Some("Engineer"));
        assert_eq!(metadata.rel_me_links, vec!["https://github.com/janedoe", "https://mastodon.social/@jane"]);
        assert_eq!(metadata.profile_links, vec!["https://github.com/janedoe", "https://x.com/janedoe"]);

        // A platform's own homepage linking to itself is not an identity signal.
        let own = parse_homepage(
            r#"<a href="https://github.com/features">f</a><a href="https://x.com/github">x</a>"#,
            &Url::parse("https://github.com/").unwrap(),
        );
        assert_eq!(own.profile_links, vec!["https://x.com/github"]);
    }

    #[test]
    fn security_txt_parsing() {
        let body = "# comment\nContact: mailto:security@example.org\nContact: https://example.org/report\nExpires: 2027-01-01T00:00:00Z\nPolicy: https://example.org/policy\n";
        let parsed = parse_security_txt("https://example.org/.well-known/security.txt", body).unwrap();
        assert_eq!(parsed.contacts.len(), 2);
        assert_eq!(parsed.expires.as_deref(), Some("2027-01-01T00:00:00Z"));
        assert!(parse_security_txt("u", "<html>not a security.txt</html>").is_none());
    }

    #[test]
    fn dns_observations_flag_weak_mail_posture() {
        let records = vec![DnsRecord { record_type: "MX".into(), value: "10 mx.example.org".into(), ttl: 60 }];
        let observations = dns_observations(&records, None, Some("v=DMARC1; p=none"));
        assert!(observations.iter().any(|text| text.contains("No SPF")));
        assert!(observations.iter().any(|text| text.contains("p=none")));
        assert!(observations.iter().any(|text| text.contains("CAA")));
    }

    #[test]
    fn rdap_parsing() {
        let document = serde_json::json!({
            "events": [{"eventAction": "registration", "eventDate": "2007-10-09T18:20:50Z"}, {"eventAction": "expiration", "eventDate": "2028-10-09T18:20:50Z"}],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "MarkMonitor Inc."]]]}],
            "status": ["client transfer prohibited"],
            "nameservers": [{"ldhName": "NS1.EXAMPLE.NET"}],
            "secureDNS": {"delegationSigned": false}
        });
        let url = Url::parse("https://rdap.example/domain/github.com").unwrap();
        let parsed = parse_rdap_domain("github.com", &url, &document);
        assert_eq!(parsed.registrar.as_deref(), Some("MarkMonitor Inc."));
        assert_eq!(parsed.registered_at.as_deref(), Some("2007-10-09T18:20:50Z"));
        assert_eq!(parsed.nameservers, vec!["ns1.example.net"]);
        assert_eq!(parsed.dnssec_signed, Some(false));
    }

    #[test]
    fn security_header_review() {
        let headers = vec![
            ("strict-transport-security".to_string(), "max-age=300".to_string()),
            ("content-security-policy".to_string(), "default-src 'self'; frame-ancestors 'none'".to_string()),
            ("server".to_string(), "nginx/1.18.0".to_string()),
        ];
        let (banner, checks) = review_security_headers(&headers);
        assert_eq!(banner.as_deref(), Some("nginx/1.18.0"));
        let find = |name: &str| checks.iter().find(|check| check.header.starts_with(name)).unwrap();
        assert!(find("Strict-Transport").note.as_deref().unwrap().contains("300"));
        assert!(find("X-Frame-Options").present, "frame-ancestors in CSP counts");
        assert!(!find("X-Content-Type-Options").present);
        assert!(find("Server banner").note.is_some());
        let (_, clean) = review_security_headers(&[("strict-transport-security".into(), "max-age=31536000; includeSubDomains".into())]);
        assert!(clean[0].note.is_none());
    }

    #[test]
    fn certificate_summary() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-11-05T00:00:00Z").unwrap().with_timezone(&chrono::Utc);
        let issuances: Vec<Issuance> = serde_json::from_value(serde_json::json!([
            {"dns_names": ["*.example.org", "example.org"], "issuer": {"friendly_name": "Let's Encrypt"}, "not_before": "2026-09-01T00:00:00Z", "not_after": "2026-12-01T00:00:00Z", "revoked": false},
            {"dns_names": ["mail.example.org", "other.test"], "issuer": {"name": "C=US, O=Example CA"}, "not_before": "2024-01-01T00:00:00Z", "not_after": "2025-01-01T00:00:00Z"}
        ]))
        .unwrap();
        let summary = summarize_issuances("example.org", issuances, now);
        assert_eq!(summary.hostnames, vec!["example.org", "mail.example.org"]);
        assert_eq!(summary.issuers, vec!["C=US, O=Example CA", "Let's Encrypt"]);
        assert_eq!((summary.certificates, summary.currently_valid), (2, 1));
        assert_eq!(summary.earliest_not_before.as_deref(), Some("2024-01-01T00:00:00Z"));
    }

    #[test]
    fn wayback_timestamps() {
        assert_eq!(wayback_timestamp("20080514210148").as_deref(), Some("2008-05-14T21:01:48Z"));
        assert_eq!(wayback_timestamp("garbage"), None);
    }
}

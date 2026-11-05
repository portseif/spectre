//! Domain intelligence: DNS configuration, RDAP registration data, and the
//! domain's public website (homepage metadata, `rel="me"` links, security.txt).

use std::collections::BTreeSet;

use async_trait::async_trait;
use scraper::{Html, Selector};
use serde::Deserialize;
use spectre_core::error::{ErrorCode, SpectreError, SpectreResult};
use spectre_core::model::{
    DiscoveryMethod, DnsRecord, DnsRecordsFinding, DomainRegistrationFinding, FindingData, SecurityTxt, VerificationStatus,
    WebPresenceFinding,
};
use spectre_core::provider::{FindingDraft, OsintProvider, ProviderCapability, ProviderContext};
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
// RDAP — RFC 9082/9083, bootstrap per RFC 9224
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
            }),
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
}

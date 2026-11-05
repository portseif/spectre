//! Email intelligence: mail-domain configuration and public Gravatar profiles.
//!
//! Deliberately absent: probing registration, login, or password-reset flows
//! to learn whether an address has an account somewhere (Holehe-style
//! enumeration). Only data the address owner chose to publish is used.

use async_trait::async_trait;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use spectre_core::error::SpectreResult;
use spectre_core::model::{
    Confidence, ConfidenceCategory, DiscoveryMethod, EmailIntelligenceFinding, FindingData, LinkedAccount, PgpKeyFinding, ProfileFinding,
    VerificationStatus,
};
use spectre_core::provider::{FindingDraft, OsintProvider, ProviderCapability, ProviderContext};
use spectre_core::target::{InvestigationTarget, TargetType};
use url::Url;

use crate::common::{attributes, base_url, endpoint, host_of, non_empty, normalize_link, observed_fact};
use crate::dns::{DohResolver, RecordType, ResponseCode, find_dmarc, find_spf, parse_mx};
use crate::provider_metadata;

// ---------------------------------------------------------------------------
// Mail domain configuration (DNS)
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct EmailDnsProvider {
    resolver: DohResolver,
}

impl EmailDnsProvider {
    pub fn with_resolver(resolver: DohResolver) -> Self {
        Self { resolver }
    }
}

#[async_trait]
impl OsintProvider for EmailDnsProvider {
    provider_metadata! {
        id: "email-dns",
        name: "Mail Domain Intelligence",
        description: "Validates address syntax and inspects the mail domain's MX, SPF, and DMARC records over DNS-over-HTTPS.",
        homepage: "https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/",
        targets: [TargetType::Email],
        capabilities: [ProviderCapability::EmailIntelligence, ProviderCapability::DnsRecords],
    }

    fn allowed_hosts(&self) -> Vec<String> {
        vec![self.resolver.host()]
    }

    fn default_rate_limit_per_minute(&self) -> u32 {
        120
    }

    async fn discover(&self, context: &ProviderContext, target: &InvestigationTarget) -> SpectreResult<Vec<FindingDraft>> {
        let InvestigationTarget::Email(email) = target else { return Ok(Vec::new()) };
        let domain = email.rsplit_once('@').map(|(_, domain)| domain.to_string()).unwrap_or_default();

        let mx_answer = self.resolver.query(context, &domain, RecordType::Mx).await?;
        let domain_resolves = mx_answer.response_code != ResponseCode::NxDomain;
        let mx_records: Vec<_> = mx_answer.records.iter().filter_map(parse_mx).collect();
        let null_mx = mx_records.len() == 1 && mx_records[0].exchange.is_empty();
        let accepts_mail = if null_mx {
            false
        } else if !mx_records.is_empty() {
            true
        } else if domain_resolves {
            // RFC 5321 section 5.1 implicit MX: fall back to the domain's address record.
            !self.resolver.query(context, &domain, RecordType::A).await?.records.is_empty()
        } else {
            false
        };
        let (spf, dmarc) = if domain_resolves {
            let root = self.resolver.txt(context, &domain).await?;
            let policy = self.resolver.txt(context, &format!("_dmarc.{domain}")).await?;
            (find_spf(&root), find_dmarc(&policy))
        } else {
            (None, None)
        };

        let summary = if !domain_resolves {
            format!("{domain} does not exist in DNS")
        } else if null_mx {
            format!("{domain} publishes a null MX and accepts no mail")
        } else if accepts_mail && mx_records.is_empty() {
            format!("{domain} has no MX record but accepts mail at its address record (RFC 5321 implicit MX)")
        } else if accepts_mail {
            format!("{domain} accepts mail ({} MX record(s))", mx_records.len())
        } else {
            format!("{domain} has no mail exchanger")
        };
        Ok(vec![FindingDraft {
            title: format!("Mail configuration for {domain}"),
            summary: Some(summary),
            confidence: observed_fact("Directly observed in public DNS"),
            verification_status: VerificationStatus::PubliclyObserved,
            sources: vec![context.source(Some(format!("dns:{domain}")), DiscoveryMethod::DnsQuery)],
            data: FindingData::EmailIntelligence(EmailIntelligenceFinding {
                email: email.clone(),
                domain,
                syntax_valid: true,
                domain_resolves,
                mx_records,
                null_mx,
                accepts_mail,
                spf,
                dmarc,
            }),
        }])
    }
}

// ---------------------------------------------------------------------------
// Gravatar: https://docs.gravatar.com/api/profiles/rest-api/
// ---------------------------------------------------------------------------

pub struct GravatarProvider {
    base: Url,
}

impl Default for GravatarProvider {
    fn default() -> Self {
        Self { base: base_url("https://api.gravatar.com/") }
    }
}

impl GravatarProvider {
    pub fn with_base(base: Url) -> Self {
        Self { base }
    }

    /// Gravatar identifies profiles by the SHA-256 of the trimmed, lowercased address.
    pub fn profile_hash(email: &str) -> String {
        hex::encode(Sha256::digest(email.trim().to_ascii_lowercase().as_bytes()))
    }
}

#[derive(Deserialize)]
struct GravatarProfile {
    display_name: Option<String>,
    profile_url: String,
    avatar_url: Option<String>,
    location: Option<String>,
    description: Option<String>,
    job_title: Option<String>,
    company: Option<String>,
    #[serde(default)]
    verified_accounts: Vec<GravatarAccount>,
}

#[derive(Deserialize)]
struct GravatarAccount {
    service_label: Option<String>,
    service_type: Option<String>,
    url: String,
    #[serde(default)]
    is_hidden: bool,
}

#[async_trait]
impl OsintProvider for GravatarProvider {
    provider_metadata! {
        id: "gravatar",
        name: "Gravatar",
        description: "Public Gravatar profiles registered to an email address, including Gravatar-verified accounts.",
        homepage: "https://gravatar.com",
        targets: [TargetType::Email],
        capabilities: [ProviderCapability::PublicEmailAssociation, ProviderCapability::ProfileLookup, ProviderCapability::LinkedAccounts],
    }

    fn allowed_hosts(&self) -> Vec<String> {
        vec![host_of(&self.base)]
    }

    async fn discover(&self, context: &ProviderContext, target: &InvestigationTarget) -> SpectreResult<Vec<FindingDraft>> {
        let InvestigationTarget::Email(email) = target else { return Ok(Vec::new()) };
        let url = endpoint(&self.base, &["v3", "profiles", &Self::profile_hash(email)]);
        let response = context.get(context.request(url.clone())).await?;
        if response.status == 404 {
            return Ok(Vec::new());
        }
        let profile: GravatarProfile = response.ensure_success()?.json()?;
        let username = profile.profile_url.trim_end_matches('/').rsplit('/').next().unwrap_or_default().to_string();
        let linked_accounts = profile
            .verified_accounts
            .into_iter()
            .filter(|account| !account.is_hidden)
            .filter_map(|account| {
                Some(LinkedAccount {
                    platform: account.service_label.or(account.service_type),
                    url: Some(normalize_link(&account.url)?),
                    verified_by_platform: true,
                    note: Some("Gravatar verified account".to_string()),
                    ..Default::default()
                })
            })
            .collect();
        let finding = ProfileFinding {
            platform: "Gravatar".to_string(),
            username,
            profile_url: profile.profile_url.clone(),
            display_name: non_empty(profile.display_name.as_deref()),
            bio: non_empty(profile.description.as_deref()),
            avatar_url: profile.avatar_url,
            location: non_empty(profile.location.as_deref()),
            linked_accounts,
            attributes: attributes([
                ("matched_by", Some("email_hash".to_string())),
                ("job_title", non_empty(profile.job_title.as_deref())),
                ("company", non_empty(profile.company.as_deref())),
            ]),
            ..Default::default()
        };
        Ok(vec![FindingDraft {
            title: format!("Gravatar profile: {}", finding.username),
            summary: finding.display_name.clone(),
            confidence: Confidence::new(
                0.8,
                ConfidenceCategory::StrongEvidence,
                [
                    "Gravatar returned a public profile for the SHA-256 hash of this exact address",
                    "Gravatar profiles are created by the address owner",
                ],
            ),
            verification_status: VerificationStatus::PubliclyObserved,
            sources: vec![
                context.source(Some(profile.profile_url), DiscoveryMethod::PublicApi),
                context.source(Some(url.to_string()), DiscoveryMethod::PublicApi),
            ],
            data: FindingData::Profile(finding),
        }])
    }
}

// ---------------------------------------------------------------------------
// OpenPGP keyserver (keys.openpgp.org): https://keys.openpgp.org/about/api
// ---------------------------------------------------------------------------

/// keys.openpgp.org only publishes a user ID after the address owner confirms
/// it by email, so a hit means the key holder proved control of the address.
pub struct OpenPgpProvider {
    base: Url,
}

impl Default for OpenPgpProvider {
    fn default() -> Self {
        Self { base: base_url("https://keys.openpgp.org/") }
    }
}

impl OpenPgpProvider {
    pub fn with_base(base: Url) -> Self {
        Self { base }
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    (byte as char).to_digit(16).map(|digit| digit as u8)
}

fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && let Some(&[high, low]) = bytes.get(index + 1..index + 3)
            && let (Some(high), Some(low)) = (hex_value(high), hex_value(low))
        {
            output.push(high << 4 | low);
            index += 3;
            continue;
        }
        output.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn pgp_algorithm(code: &str) -> String {
    match code {
        "1" | "2" | "3" => "RSA",
        "16" => "Elgamal",
        "17" => "DSA",
        "18" => "ECDH",
        "19" => "ECDSA",
        "22" => "EdDSA",
        "25" => "X25519",
        "27" => "Ed25519",
        "28" => "Ed448",
        other => return format!("algorithm {other}"),
    }
    .to_string()
}

fn epoch(raw: &str) -> Option<String> {
    raw.parse::<i64>().ok().and_then(crate::common::unix_to_rfc3339)
}

/// Parse a machine-readable HKP index (`op=index&options=mr`). Returns the
/// first key and its user IDs.
pub fn parse_hkp_index(email: &str, body: &str, keyserver: &str) -> Option<PgpKeyFinding> {
    let mut key: Option<PgpKeyFinding> = None;
    for line in body.lines() {
        let fields: Vec<&str> = line.trim().split(':').collect();
        match fields.first().copied() {
            Some("pub") if key.is_none() => {
                key = Some(PgpKeyFinding {
                    email: email.to_string(),
                    fingerprint: fields.get(1)?.to_ascii_uppercase(),
                    algorithm: fields.get(2).map(|code| pgp_algorithm(code)).unwrap_or_default(),
                    bits: fields.get(3).and_then(|bits| bits.parse().ok()),
                    created_at: fields.get(4).and_then(|value| epoch(value)),
                    expires_at: fields.get(5).and_then(|value| epoch(value)),
                    user_ids: Vec::new(),
                    keyserver: keyserver.to_string(),
                });
            }
            Some("pub") => break,
            Some("uid") => {
                if let (Some(current), Some(uid)) = (key.as_mut(), fields.get(1)) {
                    current.user_ids.push(percent_decode(uid));
                }
            }
            _ => {}
        }
    }
    key
}

#[async_trait]
impl OsintProvider for OpenPgpProvider {
    provider_metadata! {
        id: "openpgp",
        name: "OpenPGP Keyserver",
        description: "Public OpenPGP keys on keys.openpgp.org, which only lists addresses their owners have confirmed.",
        homepage: "https://keys.openpgp.org",
        targets: [TargetType::Email],
        capabilities: [ProviderCapability::PublicEmailAssociation],
    }

    fn allowed_hosts(&self) -> Vec<String> {
        vec![host_of(&self.base)]
    }

    async fn discover(&self, context: &ProviderContext, target: &InvestigationTarget) -> SpectreResult<Vec<FindingDraft>> {
        let InvestigationTarget::Email(email) = target else { return Ok(Vec::new()) };
        let mut url = endpoint(&self.base, &["pks", "lookup"]);
        url.query_pairs_mut().append_pair("op", "index").append_pair("options", "mr").append_pair("search", email);
        let response = context.get(context.request(url.clone()).accept("text/plain")).await?;
        if response.status == 404 {
            return Ok(Vec::new());
        }
        let body = response.ensure_success()?.text();
        let Some(key) = parse_hkp_index(email, &body, &host_of(&self.base)) else { return Ok(Vec::new()) };
        let short = key.fingerprint.chars().rev().take(16).collect::<Vec<_>>().into_iter().rev().collect::<String>();
        Ok(vec![FindingDraft {
            title: format!("OpenPGP key {short}"),
            summary: Some(format!("{} user ID(s), {}", key.user_ids.len(), key.algorithm)),
            confidence: observed_fact("Listed on keys.openpgp.org, which publishes an address only after its owner confirms it"),
            verification_status: VerificationStatus::PubliclyObserved,
            sources: vec![context.source(
                Some(format!(
                    "https://keys.openpgp.org/search?q={}",
                    url::form_urlencoded::byte_serialize(email.as_bytes()).collect::<String>()
                )),
                DiscoveryMethod::PublicApi,
            )],
            data: FindingData::PgpKey(key),
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gravatar_hash_matches_documented_algorithm() {
        // sha256("test@example.com")
        assert_eq!(
            GravatarProvider::profile_hash("  Test@Example.com "),
            "973dfe463ec85785f5f95af5ba3906eedb2d931c24e69824a89ea65dba4e813b"
        );
    }

    #[test]
    fn hkp_index_parsing() {
        let body = "info:1:1\npub:864C145731DD963466CC7571A2604867523C7ED8:1:3072:1559826154::\nuid:keyserver@keys.openpgp.org:1623227867::\nuid:Alice%20Example%20%3Calice@example.org%3E:1623227866::\npub:AAAA:22:256:1::\n";
        let key = parse_hkp_index("keyserver@keys.openpgp.org", body, "keys.openpgp.org").unwrap();
        assert_eq!(key.fingerprint, "864C145731DD963466CC7571A2604867523C7ED8");
        assert_eq!(key.algorithm, "RSA");
        assert_eq!(key.bits, Some(3072));
        assert_eq!(key.user_ids, vec!["keyserver@keys.openpgp.org", "Alice Example <alice@example.org>"]);
        assert!(key.created_at.unwrap().starts_with("2019-06-06"));
        assert!(parse_hkp_index("x@example.org", "info:1:0\n", "keys.openpgp.org").is_none());
    }

    #[test]
    fn percent_decoding_tolerates_bad_escapes() {
        assert_eq!(percent_decode("caf%C3%A9"), "caf\u{e9}");
        assert_eq!(percent_decode("%a\u{e9}"), "%a\u{e9}");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%+1x"), "%+1x");
    }
}

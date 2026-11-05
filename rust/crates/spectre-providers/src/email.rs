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
    Confidence, ConfidenceCategory, DiscoveryMethod, EmailIntelligenceFinding, FindingData, LinkedAccount, ProfileFinding,
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
            // RFC 5321 §5.1 implicit MX: fall back to the domain's address record.
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
// Gravatar — https://docs.gravatar.com/api/profiles/rest-api/
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
}

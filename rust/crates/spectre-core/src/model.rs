//! Domain model shared by the engine, storage, FFI, and the macOS app.
//!
//! These types are the JSON wire format across the FFI boundary. Field names
//! are snake_case; enums serialize as snake_case strings; tagged unions use an
//! explicit `kind`/`type` discriminator so they decode cleanly in Swift.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ErrorCode;
use crate::target::{InvestigationTarget, PhoneNumberInfo, TargetType};

// ---------------------------------------------------------------------------
// Investigations
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvestigationStatus {
    Pending,
    Running,
    Completed,
    PartiallyCompleted,
    Failed,
    Cancelled,
}

impl InvestigationStatus {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::PartiallyCompleted | Self::Failed | Self::Cancelled)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::PartiallyCompleted => "partially_completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Some(match raw {
            "pending" => Self::Pending,
            "running" => Self::Running,
            "completed" => Self::Completed,
            "partially_completed" => Self::PartiallyCompleted,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            _ => return None,
        })
    }
}

/// An investigation and its lifecycle metadata (without findings).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Investigation {
    pub id: Uuid,
    pub target: InvestigationTarget,
    pub target_type: TargetType,
    /// Investigator-recorded authorization basis and scope.
    pub purpose: String,
    pub status: InvestigationStatus,
    /// Fraction of providers finished, 0.0 ..= 1.0.
    pub progress: f64,
    pub providers: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub findings_count: u32,
    pub errors: Vec<ProviderFailure>,
    pub metrics: Option<InvestigationMetrics>,
}

/// A provider failure recorded against an investigation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderFailure {
    pub provider_id: String,
    pub code: ErrorCode,
    pub message: String,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderOutcome {
    Succeeded,
    NoResults,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderLatency {
    pub provider_id: String,
    pub latency_ms: u64,
    pub outcome: ProviderOutcome,
    pub findings: u32,
}

/// Measured performance of a single investigation run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvestigationMetrics {
    /// Time from the start request to the first provider being dispatched.
    pub startup_latency_ms: u64,
    pub time_to_first_finding_ms: Option<u64>,
    pub total_duration_ms: u64,
    pub provider_latencies: Vec<ProviderLatency>,
    pub http_requests: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

impl InvestigationMetrics {
    pub fn cache_hit_rate(&self) -> Option<f64> {
        let total = self.cache_hits + self.cache_misses;
        (total > 0).then(|| self.cache_hits as f64 / total as f64)
    }
}

// ---------------------------------------------------------------------------
// Confidence & verification
// ---------------------------------------------------------------------------

/// Categorical confidence. Numeric scores are evidence weights, not
/// calibrated probabilities; the category is what the UI leads with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceCategory {
    Unrelated,
    WeakEvidence,
    Possible,
    StrongEvidence,
    Confirmed,
}

impl ConfidenceCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::StrongEvidence => "strong_evidence",
            Self::Possible => "possible",
            Self::WeakEvidence => "weak_evidence",
            Self::Unrelated => "unrelated",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Some(match raw {
            "confirmed" => Self::Confirmed,
            "strong_evidence" => Self::StrongEvidence,
            "possible" => Self::Possible,
            "weak_evidence" => Self::WeakEvidence,
            "unrelated" => Self::Unrelated,
            _ => return None,
        })
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Confirmed => "Confirmed",
            Self::StrongEvidence => "Strong Evidence",
            Self::Possible => "Possible",
            Self::WeakEvidence => "Weak Evidence",
            Self::Unrelated => "Unrelated",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Confidence {
    /// Evidence weight in 0.0 ..= 1.0 (explainable, not a probability).
    pub score: f64,
    pub category: ConfidenceCategory,
    /// Human-readable reasons that produced the score.
    pub rationale: Vec<String>,
}

impl Confidence {
    pub fn new(score: f64, category: ConfidenceCategory, rationale: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self { score: score.clamp(0.0, 1.0), category, rationale: rationale.into_iter().map(Into::into).collect() }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Unverified,
    PubliclyObserved,
    OwnershipPending,
    OwnershipVerified,
}

impl VerificationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unverified => "unverified",
            Self::PubliclyObserved => "publicly_observed",
            Self::OwnershipPending => "ownership_pending",
            Self::OwnershipVerified => "ownership_verified",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Some(match raw {
            "unverified" => Self::Unverified,
            "publicly_observed" => Self::PubliclyObserved,
            "ownership_pending" => Self::OwnershipPending,
            "ownership_verified" => Self::OwnershipVerified,
            _ => return None,
        })
    }
}

/// How ownership of an email address or domain was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationMethod {
    /// A DNS TXT challenge on the domain was observed.
    DnsTxtChallenge,
    /// The address belongs to a domain verified via DNS TXT challenge.
    VerifiedDomain,
    /// The investigator attested ownership or written authorization.
    InvestigatorAttestation,
}

impl VerificationMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DnsTxtChallenge => "dns_txt_challenge",
            Self::VerifiedDomain => "verified_domain",
            Self::InvestigatorAttestation => "investigator_attestation",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Some(match raw {
            "dns_txt_challenge" => Self::DnsTxtChallenge,
            "verified_domain" => Self::VerifiedDomain,
            "investigator_attestation" => Self::InvestigatorAttestation,
            _ => return None,
        })
    }
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryMethod {
    PublicApi,
    DnsQuery,
    RdapQuery,
    PublicWebPage,
    OfflineMetadata,
    BreachApi,
    InvestigatorInput,
}

/// Where and how a piece of information was obtained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceReference {
    pub provider_id: String,
    pub provider_name: String,
    pub url: Option<String>,
    pub method: DiscoveryMethod,
    pub retrieved_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub investigation_id: Uuid,
    pub provider_id: String,
    pub title: String,
    pub summary: Option<String>,
    pub confidence: Confidence,
    pub verification_status: VerificationStatus,
    pub discovered_at: DateTime<Utc>,
    pub sources: Vec<SourceReference>,
    pub data: FindingData,
}

impl Finding {
    pub fn kind(&self) -> FindingKind {
        self.data.kind()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    Profile,
    EmailAssociation,
    EmailIntelligence,
    PhoneMetadata,
    DnsRecords,
    DomainRegistration,
    WebPresence,
    BreachIncident,
    Certificates,
    PgpKey,
    WebArchive,
}

impl FindingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Profile => "profile",
            Self::EmailAssociation => "email_association",
            Self::EmailIntelligence => "email_intelligence",
            Self::PhoneMetadata => "phone_metadata",
            Self::DnsRecords => "dns_records",
            Self::DomainRegistration => "domain_registration",
            Self::WebPresence => "web_presence",
            Self::BreachIncident => "breach_incident",
            Self::Certificates => "certificates",
            Self::PgpKey => "pgp_key",
            Self::WebArchive => "web_archive",
        }
    }
}

/// Typed payload of a finding: `{"kind": "...", "detail": {...}}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "detail", rename_all = "snake_case")]
pub enum FindingData {
    Profile(ProfileFinding),
    EmailAssociation(EmailAssociationFinding),
    EmailIntelligence(EmailIntelligenceFinding),
    PhoneMetadata(PhoneNumberInfo),
    DnsRecords(DnsRecordsFinding),
    DomainRegistration(DomainRegistrationFinding),
    WebPresence(WebPresenceFinding),
    BreachIncident(BreachFinding),
    Certificates(CertificateFinding),
    PgpKey(PgpKeyFinding),
    WebArchive(WebArchiveFinding),
}

impl FindingData {
    pub fn kind(&self) -> FindingKind {
        match self {
            Self::Profile(_) => FindingKind::Profile,
            Self::EmailAssociation(_) => FindingKind::EmailAssociation,
            Self::EmailIntelligence(_) => FindingKind::EmailIntelligence,
            Self::PhoneMetadata(_) => FindingKind::PhoneMetadata,
            Self::DnsRecords(_) => FindingKind::DnsRecords,
            Self::DomainRegistration(_) => FindingKind::DomainRegistration,
            Self::WebPresence(_) => FindingKind::WebPresence,
            Self::BreachIncident(_) => FindingKind::BreachIncident,
            Self::Certificates(_) => FindingKind::Certificates,
            Self::PgpKey(_) => FindingKind::PgpKey,
            Self::WebArchive(_) => FindingKind::WebArchive,
        }
    }
}

/// A public profile discovered on a platform.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProfileFinding {
    pub platform: String,
    pub username: String,
    pub profile_url: String,
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub avatar_url: Option<String>,
    pub website: Option<String>,
    pub location: Option<String>,
    /// Account creation date as reported by the platform.
    pub account_created_at: Option<String>,
    /// The platform itself marks the account as verified.
    pub platform_verified: bool,
    /// Email address the account owner chose to publish on the profile.
    pub public_email: Option<String>,
    /// Accounts or URLs the profile explicitly links to.
    pub linked_accounts: Vec<LinkedAccount>,
    /// Public, platform-specific counters (followers, repositories, ...).
    pub attributes: BTreeMap<String, String>,
}

/// An account or URL explicitly published by a profile owner.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedAccount {
    pub platform: Option<String>,
    pub handle: Option<String>,
    pub url: Option<String>,
    /// The hosting platform cryptographically or technically verified the link
    /// (e.g. Keybase proofs, Mastodon `rel="me"` verification).
    pub verified_by_platform: bool,
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailAssociationFinding {
    pub email: String,
    pub source_description: String,
    pub discovery_method: DiscoveryMethod,
    pub verification_status: VerificationStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxRecord {
    pub preference: u16,
    pub exchange: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailIntelligenceFinding {
    pub email: String,
    pub domain: String,
    pub syntax_valid: bool,
    pub domain_resolves: bool,
    pub mx_records: Vec<MxRecord>,
    /// RFC 7505 "null MX": the domain explicitly accepts no mail.
    pub null_mx: bool,
    pub accepts_mail: bool,
    pub spf: Option<String>,
    pub dmarc: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRecord {
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRecordsFinding {
    pub domain: String,
    pub records: Vec<DnsRecord>,
    pub spf: Option<String>,
    pub dmarc: Option<String>,
    pub observations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainRegistrationFinding {
    pub domain: String,
    pub registrar: Option<String>,
    pub registered_at: Option<String>,
    pub expires_at: Option<String>,
    pub last_changed_at: Option<String>,
    pub statuses: Vec<String>,
    pub nameservers: Vec<String>,
    pub dnssec_signed: Option<bool>,
    pub rdap_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityTxt {
    pub url: String,
    pub contacts: Vec<String>,
    pub policy: Option<String>,
    pub expires: Option<String>,
    pub encryption: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebPresenceFinding {
    pub url: String,
    pub status_code: u16,
    pub title: Option<String>,
    pub description: Option<String>,
    /// `rel="me"` links: identity assertions published by the site owner.
    pub rel_me_links: Vec<String>,
    /// Links to known social/profile platforms found on the page.
    pub profile_links: Vec<String>,
    pub security_txt: Option<SecurityTxt>,
    /// `Server` / `X-Powered-By` banners, when the site discloses them.
    #[serde(default)]
    pub server_banner: Option<String>,
    /// Passive review of security-relevant response headers.
    #[serde(default)]
    pub header_checks: Vec<HeaderCheck>,
}

/// One security header on the homepage response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderCheck {
    pub header: String,
    pub present: bool,
    pub value: Option<String>,
    /// Plain-language note when the header is missing or weak.
    pub note: Option<String>,
}

/// Certificates logged in Certificate Transparency for a domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateFinding {
    pub domain: String,
    /// Distinct hostnames seen in certificate SANs (wildcards stripped).
    pub hostnames: Vec<String>,
    pub issuers: Vec<String>,
    pub certificates: u32,
    pub currently_valid: u32,
    pub earliest_not_before: Option<String>,
    pub latest_not_after: Option<String>,
    pub source: String,
}

/// A public OpenPGP key published for an address on a verifying keyserver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PgpKeyFinding {
    pub email: String,
    pub fingerprint: String,
    pub algorithm: String,
    pub bits: Option<u32>,
    pub created_at: Option<String>,
    pub expires_at: Option<String>,
    /// User IDs the keyserver has verified (for keys.openpgp.org: confirmed addresses).
    pub user_ids: Vec<String>,
    pub keyserver: String,
}

/// Capture history of a URL in the Internet Archive's Wayback Machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebArchiveFinding {
    pub url: String,
    pub first_capture: String,
    pub last_capture: String,
    pub archive_url: String,
}

// ---------------------------------------------------------------------------
// Breach intelligence
// ---------------------------------------------------------------------------

/// Normalized public metadata about a breach incident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreachIncident {
    pub name: String,
    pub title: String,
    pub domain: Option<String>,
    /// Date the breach occurred (YYYY-MM-DD) as reported by the source.
    pub breach_date: Option<String>,
    pub added_date: Option<String>,
    pub modified_date: Option<String>,
    pub pwn_count: u64,
    /// Plain-text description (HTML removed).
    pub description: String,
    pub data_classes: Vec<String>,
    /// The breach included password data of some form. This does NOT mean a
    /// specific current password is compromised.
    pub password_data_exposed: bool,
    pub is_verified: bool,
    pub is_fabricated: bool,
    pub is_sensitive: bool,
    pub is_retired: bool,
    pub is_spam_list: bool,
    pub is_malware: bool,
    pub is_stealer_log: bool,
    pub logo_url: Option<String>,
    pub source: String,
}

/// A breach incident attached to an investigation: either an exposure of a
/// specific (ownership-verified) account, or public metadata about a breach of
/// the investigated domain's service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreachFinding {
    /// The ownership-verified address found in the breach, if this is an
    /// account exposure. `None` for service-level breach metadata.
    pub exposed_account: Option<String>,
    pub incident: BreachIncident,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskIndicator {
    pub title: String,
    pub detail: String,
    pub severity: RiskLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub level: RiskLevel,
    pub indicators: Vec<RiskIndicator>,
    pub recommendations: Vec<String>,
}

/// Breach exposure for an ownership-verified email address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreachExposureReport {
    pub email: String,
    pub verified: bool,
    pub verification_method: Option<VerificationMethod>,
    pub checked_at: DateTime<Utc>,
    pub breaches: Vec<BreachIncident>,
    pub risk: RiskAssessment,
    pub source_attribution: String,
}

// ---------------------------------------------------------------------------
// Ownership records
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailRecord {
    pub email: String,
    pub verification_status: VerificationStatus,
    pub verification_method: Option<VerificationMethod>,
    pub attestation: Option<String>,
    pub verified_at: Option<DateTime<Utc>>,
    pub last_breach_check_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainRecord {
    pub domain: String,
    pub verification_status: VerificationStatus,
    pub verification_method: Option<VerificationMethod>,
    /// TXT record value the investigator must publish.
    pub challenge_value: Option<String>,
    /// DNS name where the TXT record must be published.
    pub challenge_record_name: Option<String>,
    pub verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Identity correlation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum IdentityKind {
    Username,
    Profile,
    Email,
    Phone,
    Domain,
    Website,
    Breach,
}

impl IdentityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Username => "username",
            Self::Profile => "profile",
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Domain => "domain",
            Self::Website => "website",
            Self::Breach => "breach",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Some(match raw {
            "username" => Self::Username,
            "profile" => Self::Profile,
            "email" => Self::Email,
            "phone" => Self::Phone,
            "domain" => Self::Domain,
            "website" => Self::Website,
            "breach" => Self::Breach,
            _ => return None,
        })
    }
}

/// A node in the identity graph.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Identity {
    pub id: Uuid,
    pub kind: IdentityKind,
    pub label: String,
    /// Canonical value used for de-duplication (URL, address, handle).
    pub value: String,
    pub platform: Option<String>,
    /// The finding this identity was derived from, if any.
    pub finding_id: Option<Uuid>,
    /// True when the identity is the investigation's root target.
    pub is_target: bool,
    /// Ownership of this identity has been verified (emails, domains).
    pub verified: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipKind {
    PossibleSameOwner,
    PubliclyLinked,
    OwnershipVerified,
    ExposedInBreach,
    InvestigatorConfirmed,
}

impl RelationshipKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PossibleSameOwner => "possible_same_owner",
            Self::PubliclyLinked => "publicly_linked",
            Self::OwnershipVerified => "ownership_verified",
            Self::ExposedInBreach => "exposed_in_breach",
            Self::InvestigatorConfirmed => "investigator_confirmed",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Some(match raw {
            "possible_same_owner" => Self::PossibleSameOwner,
            "publicly_linked" => Self::PubliclyLinked,
            "ownership_verified" => Self::OwnershipVerified,
            "exposed_in_breach" => Self::ExposedInBreach,
            "investigator_confirmed" => Self::InvestigatorConfirmed,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSignal {
    ExactUsernameMatch,
    ExplicitLink,
    PlatformVerifiedLink,
    MutualLink,
    SharedWebsite,
    SharedPublicEmail,
    MatchingDisplayName,
    OwnershipVerified,
    BreachExposure,
    InvestigatorDecision,
}

/// One explainable contribution to a relationship's confidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub signal: EvidenceSignal,
    pub description: String,
    /// Contribution in 0.0 ..= 1.0, combined with noisy-OR.
    pub weight: f64,
    pub source_finding_id: Option<Uuid>,
    pub source_url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvestigatorDecision {
    Confirmed,
    Rejected,
}

impl InvestigatorDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Rejected => "rejected",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Some(match raw {
            "confirmed" => Self::Confirmed,
            "rejected" => Self::Rejected,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentityRelationship {
    pub id: Uuid,
    pub source_identity: Uuid,
    pub target_identity: Uuid,
    pub relationship: RelationshipKind,
    pub confidence: f64,
    pub category: ConfidenceCategory,
    pub evidence: Vec<EvidenceItem>,
    /// Ownership verified or investigator confirmed.
    pub verified: bool,
    pub investigator_decision: Option<InvestigatorDecision>,
}

/// Graph projection consumed by the identity graph view.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct IdentityGraph {
    pub nodes: Vec<Identity>,
    pub edges: Vec<IdentityRelationship>,
}

/// Everything known about an investigation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvestigationDetail {
    pub investigation: Investigation,
    pub findings: Vec<Finding>,
    pub graph: IdentityGraph,
}

// ---------------------------------------------------------------------------
// Streaming events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvestigationEvent {
    pub investigation_id: Uuid,
    pub sequence: u64,
    pub emitted_at: DateTime<Utc>,
    pub event: InvestigationEventKind,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InvestigationEventKind {
    Started { providers: Vec<String> },
    ProviderStarted { provider_id: String },
    FindingDiscovered { finding: Box<Finding> },
    ProviderCompleted { provider_id: String, findings: u32, latency_ms: u64 },
    ProviderFailed { failure: ProviderFailure },
    Progress { progress: f64 },
    CorrelationUpdated { identities: u32, relationships: u32 },
    Finished { status: InvestigationStatus, metrics: InvestigationMetrics },
}

impl InvestigationEventKind {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Finished { .. })
    }
}

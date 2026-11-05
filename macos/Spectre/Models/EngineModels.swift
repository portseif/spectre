import Foundation

// Swift mirrors of the Rust engine's JSON wire format (spectre-core::model).
// Keys arrive snake_case and are decoded with `.convertFromSnakeCase`; enum raw
// values are the snake_case strings the engine emits.
//
// Note: dictionary-typed fields (`attributes`, audit `detail`) have their keys
// converted to camelCase by the decoder. They are display-only and rendered
// through `String.humanizedKey`, never matched against engine constants.

// MARK: - Targets & status

enum TargetType: String, Codable, CaseIterable, Identifiable, Sendable {
    case username, email, phone, domain

    var id: String { rawValue }

    var label: String {
        switch self {
        case .username: "Username"
        case .email: "Email"
        case .phone: "Phone"
        case .domain: "Domain"
        }
    }

    var symbol: String {
        switch self {
        case .username: "at"
        case .email: "envelope"
        case .phone: "phone"
        case .domain: "globe"
        }
    }

    var placeholder: String {
        switch self {
        case .username: "octocat"
        case .email: "name@example.com"
        case .phone: "+1 650 253 0000"
        case .domain: "example.com"
        }
    }
}

struct InvestigationTarget: Codable, Hashable, Sendable {
    let type: TargetType
    let value: String
}

enum InvestigationStatus: String, Codable, Sendable {
    case pending, running, completed
    case partiallyCompleted = "partially_completed"
    case failed, cancelled

    var isTerminal: Bool {
        switch self {
        case .completed, .partiallyCompleted, .failed, .cancelled: true
        case .pending, .running: false
        }
    }

    var label: String {
        switch self {
        case .pending: "Pending"
        case .running: "Running"
        case .completed: "Completed"
        case .partiallyCompleted: "Partially Completed"
        case .failed: "Failed"
        case .cancelled: "Cancelled"
        }
    }
}

enum EngineErrorCode: String, Codable, Sendable {
    case invalidInput = "invalid_input"
    case notFound = "not_found"
    case unauthorized
    case credentialsMissing = "credentials_missing"
    case authorizationRequired = "authorization_required"
    case rateLimited = "rate_limited"
    case timeout, network
    case policyViolation = "policy_violation"
    case upstreamError = "upstream_error"
    case cancelled, storage, `internal`
}

struct ProviderFailure: Codable, Hashable, Sendable {
    let providerId: String
    let code: EngineErrorCode
    let message: String
    let occurredAt: Date
}

enum ProviderOutcome: String, Codable, Sendable {
    case succeeded
    case noResults = "no_results"
    case failed, cancelled
}

struct ProviderLatency: Codable, Hashable, Sendable {
    let providerId: String
    let latencyMs: UInt64
    let outcome: ProviderOutcome
    let findings: UInt32
}

struct InvestigationMetrics: Codable, Hashable, Sendable {
    let startupLatencyMs: UInt64
    let timeToFirstFindingMs: UInt64?
    let totalDurationMs: UInt64
    let providerLatencies: [ProviderLatency]
    let httpRequests: UInt64
    let cacheHits: UInt64
    let cacheMisses: UInt64

    var cacheHitRate: Double? {
        let total = cacheHits + cacheMisses
        return total > 0 ? Double(cacheHits) / Double(total) : nil
    }
}

struct Investigation: Codable, Hashable, Identifiable, Sendable {
    let id: UUID
    let target: InvestigationTarget
    let targetType: TargetType
    let purpose: String
    var status: InvestigationStatus
    var progress: Double
    let providers: [String]
    let createdAt: Date
    let startedAt: Date?
    let completedAt: Date?
    let findingsCount: UInt32
    let errors: [ProviderFailure]
    let metrics: InvestigationMetrics?
}

// MARK: - Confidence & verification

enum ConfidenceCategory: String, Codable, CaseIterable, Comparable, Sendable {
    case unrelated
    case weakEvidence = "weak_evidence"
    case possible
    case strongEvidence = "strong_evidence"
    case confirmed

    var label: String {
        switch self {
        case .confirmed: "Confirmed"
        case .strongEvidence: "Strong Evidence"
        case .possible: "Possible"
        case .weakEvidence: "Weak Evidence"
        case .unrelated: "Unrelated"
        }
    }

    private var rank: Int {
        switch self {
        case .unrelated: 0
        case .weakEvidence: 1
        case .possible: 2
        case .strongEvidence: 3
        case .confirmed: 4
        }
    }

    static func < (lhs: Self, rhs: Self) -> Bool { lhs.rank < rhs.rank }
}

struct Confidence: Codable, Hashable, Sendable {
    let score: Double
    let category: ConfidenceCategory
    let rationale: [String]
}

enum VerificationStatus: String, Codable, Sendable {
    case unverified
    case publiclyObserved = "publicly_observed"
    case ownershipPending = "ownership_pending"
    case ownershipVerified = "ownership_verified"

    var label: String {
        switch self {
        case .unverified: "Unverified"
        case .publiclyObserved: "Publicly Observed"
        case .ownershipPending: "Ownership Pending"
        case .ownershipVerified: "Ownership Verified"
        }
    }
}

enum VerificationMethod: String, Codable, Sendable {
    case dnsTxtChallenge = "dns_txt_challenge"
    case verifiedDomain = "verified_domain"
    case investigatorAttestation = "investigator_attestation"

    var label: String {
        switch self {
        case .dnsTxtChallenge: "DNS TXT challenge"
        case .verifiedDomain: "Verified domain"
        case .investigatorAttestation: "Investigator attestation"
        }
    }
}

// MARK: - Findings

enum DiscoveryMethod: String, Codable, Sendable {
    case publicApi = "public_api"
    case dnsQuery = "dns_query"
    case rdapQuery = "rdap_query"
    case publicWebPage = "public_web_page"
    case offlineMetadata = "offline_metadata"
    case breachApi = "breach_api"
    case investigatorInput = "investigator_input"

    var label: String {
        switch self {
        case .publicApi: "Public API"
        case .dnsQuery: "DNS query"
        case .rdapQuery: "RDAP query"
        case .publicWebPage: "Public web page"
        case .offlineMetadata: "Offline metadata"
        case .breachApi: "Breach API"
        case .investigatorInput: "Investigator input"
        }
    }
}

struct SourceReference: Codable, Hashable, Sendable {
    let providerId: String
    let providerName: String
    let url: String?
    let method: DiscoveryMethod
    let retrievedAt: Date
}

struct LinkedAccount: Codable, Hashable, Sendable {
    let platform: String?
    let handle: String?
    let url: String?
    let verifiedByPlatform: Bool
    let note: String?
}

struct ProfileFinding: Codable, Hashable, Sendable {
    let platform: String
    let username: String
    let profileUrl: String
    let displayName: String?
    let bio: String?
    let avatarUrl: String?
    let website: String?
    let location: String?
    let accountCreatedAt: String?
    let platformVerified: Bool
    let publicEmail: String?
    let linkedAccounts: [LinkedAccount]
    let attributes: [String: String]
}

struct EmailAssociationFinding: Codable, Hashable, Sendable {
    let email: String
    let sourceDescription: String
    let discoveryMethod: DiscoveryMethod
    let verificationStatus: VerificationStatus
}

struct MxRecord: Codable, Hashable, Sendable {
    let preference: UInt16
    let exchange: String
}

struct EmailIntelligenceFinding: Codable, Hashable, Sendable {
    let email: String
    let domain: String
    let syntaxValid: Bool
    let domainResolves: Bool
    let mxRecords: [MxRecord]
    let nullMx: Bool
    let acceptsMail: Bool
    let spf: String?
    let dmarc: String?
}

struct PhoneNumberInfo: Codable, Hashable, Sendable {
    let e164: String
    let internationalFormat: String
    let nationalFormat: String
    let countryCallingCode: UInt16
    let regionCode: String?
    let numberType: String
    let isValid: Bool
}

struct DnsRecord: Codable, Hashable, Sendable {
    let recordType: String
    let value: String
    let ttl: UInt32
}

struct DnsRecordsFinding: Codable, Hashable, Sendable {
    let domain: String
    let records: [DnsRecord]
    let spf: String?
    let dmarc: String?
    let observations: [String]
}

struct DomainRegistrationFinding: Codable, Hashable, Sendable {
    let domain: String
    let registrar: String?
    let registeredAt: String?
    let expiresAt: String?
    let lastChangedAt: String?
    let statuses: [String]
    let nameservers: [String]
    let dnssecSigned: Bool?
    let rdapUrl: String
}

struct SecurityTxt: Codable, Hashable, Sendable {
    let url: String
    let contacts: [String]
    let policy: String?
    let expires: String?
    let encryption: String?
}

struct HeaderCheck: Codable, Hashable, Sendable {
    let header: String
    let present: Bool
    let value: String?
    let note: String?
}

struct WebPresenceFinding: Codable, Hashable, Sendable {
    let url: String
    let statusCode: UInt16
    let title: String?
    let description: String?
    let relMeLinks: [String]
    let profileLinks: [String]
    let securityTxt: SecurityTxt?
    // Optional so findings stored before these fields existed still decode.
    let serverBanner: String?
    let headerChecks: [HeaderCheck]?
}

struct CertificateFinding: Codable, Hashable, Sendable {
    let domain: String
    let hostnames: [String]
    let issuers: [String]
    let certificates: UInt32
    let currentlyValid: UInt32
    let earliestNotBefore: String?
    let latestNotAfter: String?
    let source: String
}

struct PgpKeyFinding: Codable, Hashable, Sendable {
    let email: String
    let fingerprint: String
    let algorithm: String
    let bits: UInt32?
    let createdAt: String?
    let expiresAt: String?
    let userIds: [String]
    let keyserver: String
}

struct WebArchiveFinding: Codable, Hashable, Sendable {
    let url: String
    let firstCapture: String
    let lastCapture: String
    let archiveUrl: String
}

struct BreachIncident: Codable, Hashable, Identifiable, Sendable {
    let name: String
    let title: String
    let domain: String?
    let breachDate: String?
    let addedDate: String?
    let modifiedDate: String?
    let pwnCount: UInt64
    let description: String
    let dataClasses: [String]
    let passwordDataExposed: Bool
    let isVerified: Bool
    let isFabricated: Bool
    let isSensitive: Bool
    let isRetired: Bool
    let isSpamList: Bool
    let isMalware: Bool
    let isStealerLog: Bool
    let logoUrl: String?
    let source: String

    var id: String { name }

    var breachDay: Date? { breachDate.flatMap(EngineDate.day(from:)) }
}

struct BreachFinding: Codable, Hashable, Sendable {
    let exposedAccount: String?
    let incident: BreachIncident
}

enum FindingKind: String, Codable, CaseIterable, Sendable {
    case profile
    case emailAssociation = "email_association"
    case emailIntelligence = "email_intelligence"
    case phoneMetadata = "phone_metadata"
    case dnsRecords = "dns_records"
    case domainRegistration = "domain_registration"
    case webPresence = "web_presence"
    case breachIncident = "breach_incident"
    case certificates
    case pgpKey = "pgp_key"
    case webArchive = "web_archive"

    var label: String {
        switch self {
        case .profile: "Public Profiles"
        case .emailAssociation: "Email Associations"
        case .emailIntelligence: "Mail Domain"
        case .phoneMetadata: "Numbering Plan"
        case .dnsRecords: "DNS"
        case .domainRegistration: "Registration"
        case .webPresence: "Website"
        case .breachIncident: "Breach Exposure"
        case .certificates: "Certificates"
        case .pgpKey: "OpenPGP Keys"
        case .webArchive: "Archive History"
        }
    }

    var symbol: String {
        switch self {
        case .profile: "person.crop.circle"
        case .emailAssociation: "envelope.badge"
        case .emailIntelligence: "envelope.open"
        case .phoneMetadata: "phone.badge.waveform"
        case .dnsRecords: "network"
        case .domainRegistration: "building.columns"
        case .webPresence: "safari"
        case .breachIncident: "exclamationmark.shield"
        case .certificates: "checkmark.seal.text.page"
        case .pgpKey: "key.horizontal"
        case .webArchive: "clock.arrow.circlepath"
        }
    }
}

/// `{"kind": "...", "detail": {...}}`
enum FindingData: Codable, Hashable, Sendable {
    case profile(ProfileFinding)
    case emailAssociation(EmailAssociationFinding)
    case emailIntelligence(EmailIntelligenceFinding)
    case phoneMetadata(PhoneNumberInfo)
    case dnsRecords(DnsRecordsFinding)
    case domainRegistration(DomainRegistrationFinding)
    case webPresence(WebPresenceFinding)
    case breachIncident(BreachFinding)
    case certificates(CertificateFinding)
    case pgpKey(PgpKeyFinding)
    case webArchive(WebArchiveFinding)

    private enum CodingKeys: String, CodingKey { case kind, detail }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(FindingKind.self, forKey: .kind) {
        case .profile: self = .profile(try container.decode(ProfileFinding.self, forKey: .detail))
        case .emailAssociation: self = .emailAssociation(try container.decode(EmailAssociationFinding.self, forKey: .detail))
        case .emailIntelligence: self = .emailIntelligence(try container.decode(EmailIntelligenceFinding.self, forKey: .detail))
        case .phoneMetadata: self = .phoneMetadata(try container.decode(PhoneNumberInfo.self, forKey: .detail))
        case .dnsRecords: self = .dnsRecords(try container.decode(DnsRecordsFinding.self, forKey: .detail))
        case .domainRegistration: self = .domainRegistration(try container.decode(DomainRegistrationFinding.self, forKey: .detail))
        case .webPresence: self = .webPresence(try container.decode(WebPresenceFinding.self, forKey: .detail))
        case .breachIncident: self = .breachIncident(try container.decode(BreachFinding.self, forKey: .detail))
        case .certificates: self = .certificates(try container.decode(CertificateFinding.self, forKey: .detail))
        case .pgpKey: self = .pgpKey(try container.decode(PgpKeyFinding.self, forKey: .detail))
        case .webArchive: self = .webArchive(try container.decode(WebArchiveFinding.self, forKey: .detail))
        }
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(kind, forKey: .kind)
        switch self {
        case .profile(let detail): try container.encode(detail, forKey: .detail)
        case .emailAssociation(let detail): try container.encode(detail, forKey: .detail)
        case .emailIntelligence(let detail): try container.encode(detail, forKey: .detail)
        case .phoneMetadata(let detail): try container.encode(detail, forKey: .detail)
        case .dnsRecords(let detail): try container.encode(detail, forKey: .detail)
        case .domainRegistration(let detail): try container.encode(detail, forKey: .detail)
        case .webPresence(let detail): try container.encode(detail, forKey: .detail)
        case .breachIncident(let detail): try container.encode(detail, forKey: .detail)
        case .certificates(let detail): try container.encode(detail, forKey: .detail)
        case .pgpKey(let detail): try container.encode(detail, forKey: .detail)
        case .webArchive(let detail): try container.encode(detail, forKey: .detail)
        }
    }

    var kind: FindingKind {
        switch self {
        case .profile: .profile
        case .emailAssociation: .emailAssociation
        case .emailIntelligence: .emailIntelligence
        case .phoneMetadata: .phoneMetadata
        case .dnsRecords: .dnsRecords
        case .domainRegistration: .domainRegistration
        case .webPresence: .webPresence
        case .breachIncident: .breachIncident
        case .certificates: .certificates
        case .pgpKey: .pgpKey
        case .webArchive: .webArchive
        }
    }
}

struct Finding: Codable, Hashable, Identifiable, Sendable {
    let id: UUID
    let investigationId: UUID
    let providerId: String
    let title: String
    let summary: String?
    let confidence: Confidence
    let verificationStatus: VerificationStatus
    let discoveredAt: Date
    let sources: [SourceReference]
    let data: FindingData

    var kind: FindingKind { data.kind }

    /// Directly observed facts versus inferred identity associations.
    var isInferredAssociation: Bool {
        switch data {
        case .profile, .emailAssociation: true
        default: false
        }
    }
}

// MARK: - Breach intelligence

enum RiskLevel: String, Codable, Comparable, Sendable {
    case none, low, medium, high, critical

    var label: String { rawValue.capitalized }

    private var rank: Int {
        switch self {
        case .none: 0
        case .low: 1
        case .medium: 2
        case .high: 3
        case .critical: 4
        }
    }

    static func < (lhs: Self, rhs: Self) -> Bool { lhs.rank < rhs.rank }
}

struct RiskIndicator: Codable, Hashable, Sendable {
    let title: String
    let detail: String
    let severity: RiskLevel
}

struct RiskAssessment: Codable, Hashable, Sendable {
    let level: RiskLevel
    let indicators: [RiskIndicator]
    let recommendations: [String]
}

struct BreachExposureReport: Codable, Hashable, Sendable {
    let email: String
    let verified: Bool
    let verificationMethod: VerificationMethod?
    let checkedAt: Date
    let breaches: [BreachIncident]
    let risk: RiskAssessment
    let sourceAttribution: String
}

struct EmailRecord: Codable, Hashable, Identifiable, Sendable {
    let email: String
    let verificationStatus: VerificationStatus
    let verificationMethod: VerificationMethod?
    let attestation: String?
    let verifiedAt: Date?
    let lastBreachCheckAt: Date?
    let createdAt: Date

    var id: String { email }
}

struct DomainRecord: Codable, Hashable, Identifiable, Sendable {
    let domain: String
    let verificationStatus: VerificationStatus
    let verificationMethod: VerificationMethod?
    let challengeValue: String?
    let challengeRecordName: String?
    let verifiedAt: Date?
    let createdAt: Date

    var id: String { domain }
}

struct DomainCheckResult: Codable, Hashable, Sendable {
    let record: DomainRecord
    let verified: Bool
    let observedValues: Int
    let message: String
}

struct VerificationList: Codable, Hashable, Sendable {
    let emails: [EmailRecord]
    let domains: [DomainRecord]
}

struct CatalogSearchResult: Codable, Hashable, Sendable {
    let total: UInt64
    let breaches: [BreachIncident]
}

// MARK: - Identity graph

enum IdentityKind: String, Codable, CaseIterable, Identifiable, Sendable {
    case username, profile, email, phone, domain, website, breach

    var id: String { rawValue }

    var label: String {
        switch self {
        case .username: "Username"
        case .profile: "Public Profile"
        case .email: "Email"
        case .phone: "Phone"
        case .domain: "Domain"
        case .website: "Website"
        case .breach: "Breach"
        }
    }

    var symbol: String {
        switch self {
        case .username: "at"
        case .profile: "person.crop.circle"
        case .email: "envelope"
        case .phone: "phone"
        case .domain: "globe"
        case .website: "link"
        case .breach: "exclamationmark.shield"
        }
    }
}

struct Identity: Codable, Hashable, Identifiable, Sendable {
    let id: UUID
    let kind: IdentityKind
    let label: String
    let value: String
    let platform: String?
    let findingId: UUID?
    let isTarget: Bool
    let verified: Bool
}

enum RelationshipKind: String, Codable, CaseIterable, Identifiable, Sendable {
    case possibleSameOwner = "possible_same_owner"
    case publiclyLinked = "publicly_linked"
    case ownershipVerified = "ownership_verified"
    case exposedInBreach = "exposed_in_breach"
    case investigatorConfirmed = "investigator_confirmed"

    var id: String { rawValue }

    var label: String {
        switch self {
        case .possibleSameOwner: "Possible Association"
        case .publiclyLinked: "Publicly Linked"
        case .ownershipVerified: "Ownership Verified"
        case .exposedInBreach: "Exposed in Breach"
        case .investigatorConfirmed: "Investigator Confirmed"
        }
    }
}

enum InvestigatorDecision: String, Codable, Sendable {
    case confirmed, rejected
}

struct EvidenceItem: Codable, Hashable, Sendable {
    let signal: String
    let description: String
    let weight: Double
    let sourceFindingId: UUID?
    let sourceUrl: String?
}

struct IdentityRelationship: Codable, Hashable, Identifiable, Sendable {
    let id: UUID
    let sourceIdentity: UUID
    let targetIdentity: UUID
    let relationship: RelationshipKind
    let confidence: Double
    let category: ConfidenceCategory
    let evidence: [EvidenceItem]
    let verified: Bool
    let investigatorDecision: InvestigatorDecision?
}

struct IdentityGraph: Codable, Hashable, Sendable {
    let nodes: [Identity]
    let edges: [IdentityRelationship]

    static let empty = IdentityGraph(nodes: [], edges: [])
}

struct InvestigationDetail: Codable, Hashable, Sendable {
    var investigation: Investigation
    var findings: [Finding]
    var graph: IdentityGraph
}

// MARK: - Events

enum InvestigationEventKind: Hashable, Sendable {
    case started(providers: [String])
    case providerStarted(providerID: String)
    case findingDiscovered(Finding)
    case providerCompleted(providerID: String, findings: UInt32, latencyMs: UInt64)
    case providerFailed(ProviderFailure)
    case progress(Double)
    case correlationUpdated(identities: UInt32, relationships: UInt32)
    case finished(status: InvestigationStatus, metrics: InvestigationMetrics)

    var isTerminal: Bool {
        if case .finished = self { return true }
        return false
    }
}

extension InvestigationEventKind: Decodable {
    private enum CodingKeys: String, CodingKey {
        case type, providers, providerId, finding, findings, latencyMs, failure, progress, identities, relationships, status, metrics
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let type = try container.decode(String.self, forKey: .type)
        switch type {
        case "started": self = .started(providers: try container.decode([String].self, forKey: .providers))
        case "provider_started": self = .providerStarted(providerID: try container.decode(String.self, forKey: .providerId))
        case "finding_discovered": self = .findingDiscovered(try container.decode(Finding.self, forKey: .finding))
        case "provider_completed":
            self = .providerCompleted(
                providerID: try container.decode(String.self, forKey: .providerId),
                findings: try container.decode(UInt32.self, forKey: .findings),
                latencyMs: try container.decode(UInt64.self, forKey: .latencyMs)
            )
        case "provider_failed": self = .providerFailed(try container.decode(ProviderFailure.self, forKey: .failure))
        case "progress": self = .progress(try container.decode(Double.self, forKey: .progress))
        case "correlation_updated":
            self = .correlationUpdated(
                identities: try container.decode(UInt32.self, forKey: .identities),
                relationships: try container.decode(UInt32.self, forKey: .relationships)
            )
        case "finished":
            self = .finished(
                status: try container.decode(InvestigationStatus.self, forKey: .status),
                metrics: try container.decode(InvestigationMetrics.self, forKey: .metrics)
            )
        default:
            throw DecodingError.dataCorruptedError(forKey: .type, in: container, debugDescription: "unknown event type \(type)")
        }
    }
}

struct InvestigationEvent: Decodable, Hashable, Sendable {
    let investigationId: UUID
    let sequence: UInt64
    let emittedAt: Date
    let event: InvestigationEventKind
}

struct EventBatch: Decodable, Sendable {
    let events: [InvestigationEvent]
    let finished: Bool
    let unknown: Bool
}

// MARK: - Settings & providers

struct EngineSettings: Codable, Hashable, Sendable {
    var maxConcurrency: UInt32
    var requestTimeoutSecs: UInt32
    var providerTimeoutSecs: UInt32
    var cacheTtlSecs: UInt32
    var maxRetries: UInt32
    var retryBaseDelayMs: UInt32
    var defaultRateLimitPerMinute: UInt32
    var retentionDays: UInt32

    static let defaults = EngineSettings(
        maxConcurrency: 4, requestTimeoutSecs: 15, providerTimeoutSecs: 45, cacheTtlSecs: 900,
        maxRetries: 2, retryBaseDelayMs: 400, defaultRateLimitPerMinute: 30, retentionDays: 0
    )
}

struct CredentialRequirement: Codable, Hashable, Sendable {
    let type: String
    let credentialId: String?
    let purpose: String?
}

struct ProviderStatus: Codable, Hashable, Identifiable, Sendable {
    let id: String
    let name: String
    let description: String
    let homepage: String
    let supportedTargets: [TargetType]
    let capabilities: [String]
    let credential: CredentialRequirement
    let allowedHosts: [String]
    let defaultRateLimitPerMinute: UInt32
    let usesNetwork: Bool
    var enabled: Bool
    var rateLimitPerMinute: UInt32
    let credentialConfigured: Bool
}

struct ServiceStatus: Codable, Hashable, Identifiable, Sendable {
    let id: String
    let name: String
    let description: String
    let credentialId: String?
    let credentialRequired: Bool
    let credentialConfigured: Bool
    let hosts: [String]
}

struct ProviderListing: Codable, Hashable, Sendable {
    let providers: [ProviderStatus]
    let services: [ServiceStatus]
}

// MARK: - Dashboard, audit, diagnostics

struct CountByLabel: Codable, Hashable, Identifiable, Sendable {
    let label: String
    let count: UInt64
    var id: String { label }
}

struct DashboardStats: Codable, Hashable, Sendable {
    let investigations: UInt64
    let running: UInt64
    let findings: UInt64
    let profiles: UInt64
    let confirmedRelationships: UInt64
    let strongRelationships: UInt64
    let verifiedEmails: UInt64
    let breachExposures: UInt64
    let findingsByProvider: [CountByLabel]
    let findingsByCategory: [CountByLabel]
    let investigationsByDay: [CountByLabel]
    let exposuresByYear: [CountByLabel]
}

struct PasswordCheckResult: Codable, Hashable, Sendable {
    let compromised: Bool
    let occurrences: UInt64
    let recommendation: String
    let checkedAt: Date
    let rangeSize: UInt32
}

enum HashStrength: String, Codable, Comparable, Sendable {
    case critical, weak, acceptable, strong, unknown

    var label: String { rawValue.capitalized }

    private var rank: Int {
        switch self {
        case .critical: 0
        case .weak: 1
        case .acceptable: 2
        case .strong: 3
        case .unknown: 4
        }
    }

    static func < (lhs: Self, rhs: Self) -> Bool { lhs.rank < rhs.rank }
}

struct SchemeSummary: Codable, Hashable, Identifiable, Sendable {
    let scheme: String
    let label: String
    let count: UInt64
    let salted: Bool?
    let strength: HashStrength
    let parameters: [String: UInt64]

    var id: String { "\(scheme)-\(strength.rawValue)" }
}

struct HashInventory: Codable, Hashable, Sendable {
    let linesRead: UInt64
    let hashesAnalyzed: UInt64
    let accountsWithoutPassword: UInt64
    let schemes: [SchemeSummary]
    let duplicateValues: UInt64
    let unsaltedCount: UInt64
    let overall: HashStrength
    let recommendations: [String]
}

struct AuditEvent: Decodable, Hashable, Identifiable, Sendable {
    let id: UUID
    let investigationId: UUID?
    let eventType: String
    let detail: JSONValue
    let createdAt: Date
}

struct StorageInfo: Codable, Hashable, Sendable {
    let path: String?
    let schemaVersion: Int64
    let sizeBytes: UInt64
    let pageCount: Int64
    let freelistPages: Int64
}

struct Diagnostics: Codable, Hashable, Sendable {
    let engineVersion: String
    let storage: StorageInfo
    let providers: Int
    let activeInvestigations: Int
    let httpRequests: UInt64
    let cacheHits: UInt64
    let cacheMisses: UInt64
    let cacheEntries: Int
    let retries: UInt64
    let allowedHosts: [String]
    let credentialsConfigured: [String]
    let uptimeSeconds: UInt64
}

/// An identifier the findings point to. Starting it is always the
/// investigator's call, with its own authorization record.
struct FollowUp: Codable, Hashable, Identifiable, Sendable {
    let targetType: TargetType
    let value: String
    let reason: String
    let sourceFindingId: UUID?
    let alreadyInvestigated: Bool

    var id: String { "\(targetType.rawValue):\(value)" }
}

struct TargetValidation: Codable, Hashable, Sendable {
    let valid: Bool
    let normalized: String?
    let phone: PhoneNumberInfo?
    let error: String?
}

// MARK: - Generic JSON

/// Arbitrary JSON for display-only payloads.
enum JSONValue: Codable, Hashable, Sendable {
    case string(String), number(Double), bool(Bool), object([String: JSONValue]), array([JSONValue]), null

    init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() { self = .null }
        else if let value = try? container.decode(Bool.self) { self = .bool(value) }
        else if let value = try? container.decode(Double.self) { self = .number(value) }
        else if let value = try? container.decode(String.self) { self = .string(value) }
        else if let value = try? container.decode([JSONValue].self) { self = .array(value) }
        else { self = .object(try container.decode([String: JSONValue].self)) }
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let value): try container.encode(value)
        case .number(let value): try container.encode(value)
        case .bool(let value): try container.encode(value)
        case .object(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .null: try container.encodeNil()
        }
    }

    var displayText: String {
        switch self {
        case .string(let value): value
        case .number(let value): value.rounded() == value ? String(Int64(value)) : String(value)
        case .bool(let value): value ? "yes" : "no"
        case .null: "none"
        case .array(let values): values.map(\.displayText).joined(separator: ", ")
        case .object(let values):
            values.sorted { $0.key < $1.key }.map { "\($0.key.humanizedKey): \($0.value.displayText)" }.joined(separator: " · ")
        }
    }
}

extension String {
    /// Turns `publicRepositories` or `public_repositories` into `Public repositories`.
    var humanizedKey: String {
        var words: [String] = []
        var current = ""
        for character in self {
            if character == "_" || character == " " {
                if !current.isEmpty { words.append(current) }
                current = ""
            } else if character.isUppercase, !current.isEmpty {
                words.append(current)
                current = String(character).lowercased()
            } else {
                current.append(character)
            }
        }
        if !current.isEmpty { words.append(current) }
        let sentence = words.joined(separator: " ").lowercased()
        return sentence.prefix(1).uppercased() + sentence.dropFirst()
    }
}

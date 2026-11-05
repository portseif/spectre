import Foundation

/// Representative sample data for SwiftUI previews and UI tests. Values are
/// synthetic; shapes match the engine's wire format.
enum PreviewData {
    static let investigationID = UUID(uuidString: "5B1F5A3E-0000-4000-8000-000000000001")!
    static let now = Date(timeIntervalSince1970: 1_793_840_000)

    static func source(_ provider: String, _ url: String?) -> SourceReference {
        SourceReference(providerId: provider.lowercased(), providerName: provider, url: url, method: .publicApi, retrievedAt: now)
    }

    static func profile(_ platform: String, username: String = "exampleuser", category: ConfidenceCategory = .weakEvidence, links: [LinkedAccount] = []) -> Finding {
        let url = "https://\(platform.lowercased()).example/\(username)"
        return Finding(
            id: UUID(),
            investigationId: investigationID,
            providerId: platform.lowercased(),
            title: "\(platform) profile: \(username)",
            summary: "Example User",
            confidence: Confidence(score: category == .weakEvidence ? 0.35 : 0.82, category: category, rationale: [
                "\(platform) username \"\(username)\" matches \"\(username)\"",
                "A matching username alone does not establish common ownership",
            ]),
            verificationStatus: .publiclyObserved,
            discoveredAt: now,
            sources: [source(platform, url)],
            data: .profile(ProfileFinding(
                platform: platform, username: username, profileUrl: url, displayName: "Example User", bio: "Builds things.",
                avatarUrl: nil, website: "https://example.dev/", location: "Earth", accountCreatedAt: "2015-01-01T00:00:00Z",
                platformVerified: false, publicEmail: nil, linkedAccounts: links, attributes: ["followers": "42", "publicRepositories": "12"]
            ))
        )
    }

    static let dnsFinding = Finding(
        id: UUID(), investigationId: investigationID, providerId: "domain-dns", title: "DNS records for example.org",
        summary: "6 record(s); 2 observation(s)",
        confidence: Confidence(score: 1, category: .confirmed, rationale: ["Directly observed in public DNS"]),
        verificationStatus: .publiclyObserved, discoveredAt: now, sources: [source("DNS Records", "dns:example.org")],
        data: .dnsRecords(DnsRecordsFinding(
            domain: "example.org",
            records: [DnsRecord(recordType: "A", value: "93.184.215.14", ttl: 300), DnsRecord(recordType: "MX", value: "10 mx.example.org", ttl: 300)],
            spf: "v=spf1 -all", dmarc: nil, observations: ["No DMARC policy published at _dmarc", "No CAA record: any certificate authority may issue certificates for the domain"]
        ))
    )

    static let breach = BreachIncident(
        name: "ExampleBreach", title: "Example Breach", domain: "example.com", breachDate: "2022-04-15", addedDate: "2022-05-01T00:00:00Z",
        modifiedDate: nil, pwnCount: 1_250_000, description: "In April 2022, the example service suffered a breach.",
        dataClasses: ["Email addresses", "Passwords", "Usernames"], passwordDataExposed: true, isVerified: true, isFabricated: false,
        isSensitive: false, isRetired: false, isSpamList: false, isMalware: false, isStealerLog: false, logoUrl: nil, source: "Have I Been Pwned"
    )

    static var findings: [Finding] {
        [
            profile("GitHub", category: .strongEvidence, links: [LinkedAccount(platform: "X", handle: "example_x", url: "https://x.com/example_x", verifiedByPlatform: false, note: nil)]),
            profile("Codeberg"),
            profile("Keybase", category: .possible),
            dnsFinding,
        ]
    }

    static let metrics = InvestigationMetrics(
        startupLatencyMs: 2, timeToFirstFindingMs: 480, totalDurationMs: 2350,
        providerLatencies: [
            ProviderLatency(providerId: "github", latencyMs: 640, outcome: .succeeded, findings: 1),
            ProviderLatency(providerId: "gitlab", latencyMs: 410, outcome: .noResults, findings: 0),
        ],
        httpRequests: 14, cacheHits: 2, cacheMisses: 12
    )

    static let investigation = Investigation(
        id: investigationID, target: InvestigationTarget(type: .username, value: "exampleuser"), targetType: .username,
        purpose: "Authorized self-assessment of my public footprint", status: .completed, progress: 1,
        providers: ["github", "gitlab", "codeberg", "keybase"], createdAt: now, startedAt: now, completedAt: now.addingTimeInterval(2.35),
        findingsCount: 4, errors: [ProviderFailure(providerId: "gitlab", code: .rateLimited, message: "gitlab.com rate limit exceeded", occurredAt: now)],
        metrics: metrics
    )

    static var graph: IdentityGraph {
        let root = Identity(id: UUID(), kind: .username, label: "exampleuser", value: "exampleuser", platform: nil, findingId: nil, isTarget: true, verified: false)
        let profiles = findings.prefix(3).map { finding in
            Identity(id: UUID(), kind: .profile, label: finding.title, value: finding.title, platform: finding.providerId, findingId: finding.id, isTarget: false, verified: false)
        }
        let linked = Identity(id: UUID(), kind: .profile, label: "x.com/example_x", value: "x.com/example_x", platform: "X", findingId: nil, isTarget: false, verified: false)
        let edges = profiles.enumerated().map { index, node in
            IdentityRelationship(
                id: UUID(), sourceIdentity: root.id, targetIdentity: node.id, relationship: .possibleSameOwner,
                confidence: [0.82, 0.35, 0.45][index], category: [.strongEvidence, .weakEvidence, .possible][index],
                evidence: [EvidenceItem(signal: "exact_username_match", description: "Username matches", weight: 0.35, sourceFindingId: node.findingId, sourceUrl: nil)],
                verified: false, investigatorDecision: nil
            )
        } + [IdentityRelationship(
            id: UUID(), sourceIdentity: profiles[0].id, targetIdentity: linked.id, relationship: .publiclyLinked, confidence: 0.6,
            category: .possible, evidence: [EvidenceItem(signal: "explicit_link", description: "GitHub profile links to x.com/example_x", weight: 0.6, sourceFindingId: nil, sourceUrl: "https://x.com/example_x")],
            verified: false, investigatorDecision: nil
        )]
        return IdentityGraph(nodes: [root] + profiles + [linked], edges: edges)
    }

    static var detail: InvestigationDetail {
        InvestigationDetail(investigation: investigation, findings: findings, graph: graph)
    }

    static let report = BreachExposureReport(
        email: "owner@example.org", verified: true, verificationMethod: .investigatorAttestation, checkedAt: now, breaches: [breach],
        risk: RiskAssessment(
            level: .high,
            indicators: [RiskIndicator(title: "Example Breach: password data exposed", detail: "The breach (2022-04-15) contained password data in some form (often hashed). This does not prove a current password is known.", severity: .high)],
            recommendations: ["Change the password for each affected service and anywhere the same password was reused.", "Enable multi-factor authentication on the email account and on affected services."]
        ),
        sourceAttribution: "Have I Been Pwned (haveibeenpwned.com), licensed under CC BY 4.0"
    )

    static let dashboard = DashboardStats(
        investigations: 12, running: 1, findings: 148, profiles: 96, confirmedRelationships: 3, strongRelationships: 11, verifiedEmails: 2,
        breachExposures: 5,
        findingsByProvider: [CountByLabel(label: "github", count: 12), CountByLabel(label: "keybase", count: 9), CountByLabel(label: "domain-dns", count: 4)],
        findingsByCategory: [CountByLabel(label: "weak_evidence", count: 80), CountByLabel(label: "possible", count: 30), CountByLabel(label: "confirmed", count: 38)],
        investigationsByDay: [CountByLabel(label: "2026-11-03", count: 3), CountByLabel(label: "2026-11-04", count: 5), CountByLabel(label: "2026-11-05", count: 4)],
        exposuresByYear: [CountByLabel(label: "2013", count: 1), CountByLabel(label: "2019", count: 2), CountByLabel(label: "2022", count: 2)]
    )
}

/// Engine stand-in for previews: serves `PreviewData` without the Rust library.
struct PreviewEngine: EngineClient {
    func investigations(search: String?) async throws -> [Investigation] { [PreviewData.investigation] }
    func investigation(_ id: UUID) async throws -> InvestigationDetail { PreviewData.detail }
    func dashboard() async throws -> DashboardStats { PreviewData.dashboard }
    func validateTarget(_ type: TargetType, value: String, region: String?) async throws -> TargetValidation {
        TargetValidation(valid: !value.isEmpty, normalized: value.lowercased(), phone: nil, error: value.isEmpty ? "Value is empty" : nil)
    }
    func storedExposures(email: String) async throws -> BreachExposureReport { PreviewData.report }
}

import Foundation
import PDFKit
import Testing
@testable import Spectre

@Suite("Support")
struct SupportTests {
    @Test func parsesEngineTimestamps() throws {
        let micro = try #require(EngineDate.parse("2026-11-05T01:05:20.492045Z"))
        let whole = try #require(EngineDate.parse("2026-11-05T01:05:20Z"))
        #expect(abs(micro.timeIntervalSince(whole) - 0.492045) < 0.000_01)
        #expect(EngineDate.parse("2026-11-05T01:05:20.5+02:00") != nil)
        #expect(EngineDate.day(from: "2022-04-15") != nil)
        #expect(EngineDate.parse("not a date") == nil)
    }

    @Test func decodesFindingsFromEngineJSON() throws {
        let json = """
        {"id":"8b5b2f86-3a5b-4f8e-9d1e-1f2a3b4c5d6e","investigation_id":"5b1f5a3e-0000-4000-8000-000000000001","provider_id":"github",
         "title":"GitHub profile: octo","summary":null,"confidence":{"score":0.35,"category":"weak_evidence","rationale":["r"]},
         "verification_status":"publicly_observed","discovered_at":"2026-11-05T01:05:20.492045Z",
         "sources":[{"provider_id":"github","provider_name":"GitHub","url":"https://github.com/octo","method":"public_api","retrieved_at":"2026-11-05T01:05:20.492045Z"}],
         "data":{"kind":"profile","detail":{"platform":"GitHub","username":"octo","profile_url":"https://github.com/octo","display_name":null,"bio":null,
         "avatar_url":null,"website":null,"location":null,"account_created_at":null,"platform_verified":false,"public_email":null,
         "linked_accounts":[{"platform":"X","handle":"octo","url":"https://x.com/octo","verified_by_platform":true,"note":null}],"attributes":{"public_repositories":"3"}}}}
        """
        let finding = try EngineCoding.decoder().decode(Finding.self, from: Data(json.utf8))
        #expect(finding.confidence.category == .weakEvidence)
        guard case .profile(let profile) = finding.data else {
            Issue.record("expected profile")
            return
        }
        #expect(profile.linkedAccounts.first?.verifiedByPlatform == true)
        #expect(profile.attributes.keys.first?.humanizedKey == "Public repositories")
    }

    @Test func pdfReportSeparatesConfirmedAndInferred() throws {
        let data = ReportGenerator.pdf(for: PreviewData.detail, generatedAt: PreviewData.now)
        let document = try #require(PDFDocument(data: data))
        #expect(document.pageCount >= 1)
        let text = document.string ?? ""
        #expect(text.contains("Confirmed identity associations"))
        #expect(text.contains("Inferred associations"))
        #expect(text.contains("Evidence sources"))
        #expect(text.contains("Remediation recommendations"))
    }

    @Test func graphFilterCollapsesLeavesAndFiltersConfidence() {
        let graph = PreviewData.graph
        var filter = GraphFilter()
        #expect(filter.visibleGraph(graph).nodes.count == graph.nodes.count)
        let github = graph.nodes[1]
        #expect(filter.collapsibleCount(of: github.id, in: graph) == 1, "the linked X account hangs only off GitHub")
        filter.collapsed.insert(github.id)
        #expect(filter.visibleGraph(graph).nodes.count == graph.nodes.count - 1)

        filter = GraphFilter(minimumCategory: .possible)
        let strong = filter.visibleGraph(graph)
        #expect(strong.edges.allSatisfy { $0.category >= .possible })
        #expect(strong.nodes.contains { $0.isTarget })
    }

    @Test func graphLayoutIsDeterministic() {
        let graph = PreviewData.graph
        let layout = GraphLayout(nodes: graph.nodes.map(\.id), edges: graph.edges.map { .init(source: $0.sourceIdentity, target: $0.targetIdentity, weight: $0.confidence) }, pinned: graph.nodes[0].id)
        let first = layout.positions(iterations: 50)
        let second = layout.positions(iterations: 50)
        #expect(first == second)
        #expect(first[graph.nodes[0].id] == .zero)
    }

    @Test func decodesNewFindingTypesAndOlderWebFindings() throws {
        let decoder = EngineCoding.decoder()
        let certificates = try decoder.decode(FindingData.self, from: Data("""
        {"kind":"certificates","detail":{"domain":"example.org","hostnames":["example.org","mail.example.org"],"issuers":["Let's Encrypt"],
         "certificates":3,"currently_valid":1,"earliest_not_before":"2024-01-01T00:00:00Z","latest_not_after":null,"source":"Cert Spotter"}}
        """.utf8))
        guard case .certificates(let detail) = certificates else { Issue.record("expected certificates"); return }
        #expect(detail.currentlyValid == 1)

        // Findings saved before header checks existed have no such keys.
        let older = try decoder.decode(FindingData.self, from: Data("""
        {"kind":"web_presence","detail":{"url":"https://example.org/","status_code":200,"title":null,"description":null,
         "rel_me_links":[],"profile_links":[],"security_txt":null}}
        """.utf8))
        guard case .webPresence(let web) = older else { Issue.record("expected web presence"); return }
        #expect(web.headerChecks == nil)

        let followUp = try decoder.decode(FollowUp.self, from: Data("""
        {"target_type":"username","value":"octo_x","reason":"X account linked from the GitHub profile","source_finding_id":null,"already_investigated":true}
        """.utf8))
        #expect(followUp.alreadyInvestigated)
        #expect(followUp.id == "username:octo_x")
    }

    @Test func manualSearchLinksQuoteAndEncodeTheTarget() {
        let links = ManualSearch.links(for: InvestigationTarget(type: .domain, value: "example.org"))
        #expect(links.count == 6)
        #expect(links.allSatisfy { $0.url.scheme == "https" })
        #expect(links[0].url.absoluteString.contains("%22example.org%22"))
        let email = ManualSearch.links(for: InvestigationTarget(type: .email, value: "a+b@example.org"))
        #expect(email.contains { $0.url.absoluteString.contains("a%2Bb") }, "plus signs must not turn into spaces")
    }

    @MainActor
    @Test func preparingAFollowUpPrefillsTheForm() {
        let model = AppModel(engine: PreviewEngine())
        model.prepareInvestigation(type: .username, value: "octo_x")
        #expect(model.selection == .newInvestigation)
        #expect(model.draftTarget == DraftTarget(type: .username, value: "octo_x"))
    }
}

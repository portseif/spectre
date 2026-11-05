import Foundation
import Testing
@testable import Spectre

/// Exercises the real Rust engine through the C ABI. Every test uses offline
/// providers or local-only operations: no live external APIs.
@Suite("Rust engine integration", .serialized)
struct RustEngineIntegrationTests {
    private func temporaryDatabase() -> URL {
        FileManager.default.temporaryDirectory.appending(path: "spectre-tests-\(UUID().uuidString)").appending(path: "test.sqlite")
    }

    @Test func versionIsExposed() {
        #expect(!RustEngine.version.isEmpty)
    }

    @Test func validatesAndNormalizesTargets() async throws {
        let engine = try RustEngine(databaseURL: nil)
        let email = try await engine.validateTarget(.email, value: "  Alice@Example.COM ", region: nil)
        #expect(email.valid)
        #expect(email.normalized == "alice@example.com")

        let phone = try await engine.validateTarget(.phone, value: "020 7946 0958", region: "GB")
        #expect(phone.normalized == "+442079460958")
        #expect(phone.phone?.regionCode == "GB")

        let blocked = try await engine.validateTarget(.domain, value: "localhost", region: nil)
        #expect(!blocked.valid)
        #expect(blocked.error != nil)
    }

    @Test func runsAnOfflineInvestigationEndToEnd() async throws {
        let engine = try RustEngine(databaseURL: nil)
        let investigation = try await engine.startInvestigation(StartInvestigationRequest(
            targetType: .phone, value: "+1 650 253 0000", purpose: "Integration test of numbering metadata",
            providerIds: ["phone-numbering"], defaultRegion: nil
        ))
        #expect(investigation.target.value == "+16502530000")

        var kinds: [String] = []
        for try await event in engine.events(for: investigation.id) {
            switch event.event {
            case .started: kinds.append("started")
            case .findingDiscovered: kinds.append("finding")
            case .finished(let status, _):
                kinds.append("finished")
                #expect(status == .completed)
            default: break
            }
        }
        #expect(kinds.first == "started")
        #expect(kinds.contains("finding"))
        #expect(kinds.last == "finished")

        let detail = try await engine.investigation(investigation.id)
        #expect(detail.investigation.status == .completed)
        #expect(detail.findings.count == 1)
        guard case .phoneMetadata(let phone) = detail.findings.first?.data else {
            Issue.record("expected phone metadata")
            return
        }
        #expect(phone.countryCallingCode == 1)
        #expect(detail.graph.nodes.contains { $0.isTarget })

        let csv = try await engine.exportCSV(investigation.id)
        #expect(csv.split(separator: "\n").count == 2)
        let json = try await engine.exportJSON(investigation.id)
        let object = try #require(try JSONSerialization.jsonObject(with: json) as? [String: Any])
        #expect(object["format"] as? String == "spectre.investigation")
    }

    @Test func rejectsInvestigationsWithoutAuthorizationRecord() async throws {
        let engine = try RustEngine(databaseURL: nil)
        await #expect(throws: EngineError.self) {
            try await engine.startInvestigation(StartInvestigationRequest(targetType: .phone, value: "+16502530000", purpose: "short", providerIds: nil, defaultRegion: nil))
        }
        do {
            _ = try await engine.startInvestigation(StartInvestigationRequest(targetType: .phone, value: "+16502530000", purpose: "x", providerIds: nil, defaultRegion: nil))
        } catch let error as EngineError {
            #expect(error.code == .authorizationRequired)
        }
    }

    @Test func settingsPersistAcrossEngineInstances() async throws {
        let database = temporaryDatabase()
        do {
            let engine = try RustEngine(databaseURL: database)
            var settings = try await engine.settings()
            settings.maxConcurrency = 7
            settings.cacheTtlSecs = 120
            _ = try await engine.updateSettings(settings)
        }
        let reopened = try RustEngine(databaseURL: database)
        let loaded = try await reopened.settings()
        #expect(loaded.maxConcurrency == 7)
        #expect(loaded.cacheTtlSecs == 120)
    }

    @Test func breachLookupRequiresVerifiedOwnership() async throws {
        let engine = try RustEngine(databaseURL: nil)
        do {
            _ = try await engine.lookupBreaches(email: "someone@example.org", investigationID: nil)
            Issue.record("lookup must be refused")
        } catch let error as EngineError {
            #expect(error.code == .authorizationRequired)
        }
        let record = try await engine.attestEmail("someone@example.org", statement: "Test mailbox owned by the test suite")
        #expect(record.verificationStatus == .ownershipVerified)
        // Without an API key the engine refuses before any network request.
        do {
            _ = try await engine.lookupBreaches(email: "someone@example.org", investigationID: nil)
            Issue.record("lookup must require a key")
        } catch let error as EngineError {
            #expect(error.code == .credentialsMissing)
        }
    }

    @Test func hashInventoryAndPasswordValidationAreLocal() async throws {
        let engine = try RustEngine(databaseURL: nil)
        let inventory = try await engine.hashInventory("alice:$2b$12$KIXQJm0p0yQxQ1Lw7VbKQe2z0Yp0u5vD9n9H1l3uQ1mJ1qJ1qJ1qG\nbob:5f4dcc3b5aa765d61d8327deb882cf99\n")
        #expect(inventory.hashesAnalyzed == 2)
        #expect(inventory.overall == .critical)
        #expect(inventory.unsaltedCount == 1)
        do {
            _ = try await engine.checkPassword("")
            Issue.record("empty passwords must be rejected")
        } catch let error as EngineError {
            #expect(error.code == .invalidInput)
        }
    }

    @Test func providerCatalogDecodes() async throws {
        let engine = try RustEngine(databaseURL: nil)
        let listing = try await engine.providers()
        #expect(listing.providers.count >= 19)
        #expect(listing.providers.contains { $0.id == "github" && $0.supportedTargets == [.username] })
        #expect(listing.services.map(\.id).sorted() == ["hibp", "pwned-passwords"])
    }
}

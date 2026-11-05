import Foundation
import Testing
@testable import Spectre

/// Scripted engine for view-model state-transition tests.
final class ScriptedEngine: EngineClient, @unchecked Sendable {
    let investigation: Investigation
    var script: [InvestigationEventKind]
    var detail: InvestigationDetail
    private(set) var cancelled = false
    private let lock = NSLock()

    init(investigation: Investigation, script: [InvestigationEventKind], detail: InvestigationDetail) {
        self.investigation = investigation
        self.script = script
        self.detail = detail
    }

    func startInvestigation(_ request: StartInvestigationRequest) async throws -> Investigation { investigation }
    func investigation(_ id: UUID) async throws -> InvestigationDetail { lock.withLock { detail } }
    func investigations(search: String?) async throws -> [Investigation] { [investigation] }
    func cancelInvestigation(_ id: UUID) async throws { lock.withLock { cancelled = true } }

    func events(for id: UUID) -> AsyncThrowingStream<InvestigationEvent, any Error> {
        let script = script
        return AsyncThrowingStream { continuation in
            for (index, kind) in script.enumerated() {
                continuation.yield(InvestigationEvent(investigationId: id, sequence: UInt64(index + 1), emittedAt: .now, event: kind))
            }
            continuation.finish()
        }
    }
}

@MainActor
@Suite("Investigation view model")
struct InvestigationViewModelTests {
    private func pending() -> Investigation {
        var investigation = PreviewData.investigation
        investigation.status = .pending
        investigation.progress = 0
        return investigation
    }

    @Test func streamingTransitionsToLoaded() async throws {
        let finding = PreviewData.findings[0]
        var completed = PreviewData.detail
        completed.findings = [finding]
        let engine = ScriptedEngine(investigation: pending(), script: [
            .started(providers: ["github", "gitlab"]),
            .providerStarted(providerID: "github"),
            .findingDiscovered(finding),
            .providerCompleted(providerID: "github", findings: 1, latencyMs: 120),
            .providerFailed(ProviderFailure(providerId: "gitlab", code: .rateLimited, message: "slow down", occurredAt: .now)),
            .progress(1),
            .finished(status: .partiallyCompleted, metrics: PreviewData.metrics),
        ], detail: completed)
        let model = InvestigationViewModel(id: PreviewData.investigationID, engine: engine, initial: nil)
        model.begin(with: pending())
        #expect(model.phase == .streaming)

        try await waitUntil { model.phase == .loaded }
        #expect(model.findings.count == 1)
        #expect(model.sections.map(\.kind) == [.profile])
        // After the stream ends the stored run metrics are authoritative.
        #expect(model.providerStates["github"] == .completed(findings: 1, latencyMs: 640))
        #expect(model.providerStates["gitlab"] == .failed(code: .rateLimited, message: "gitlab.com rate limit exceeded"))
        #expect(model.status == .completed, "reload after finish takes the stored detail")
    }

    @Test func eventsApplyInOrderAndIgnoreDuplicates() {
        let engine = ScriptedEngine(investigation: pending(), script: [], detail: PreviewData.detail)
        let model = InvestigationViewModel(id: PreviewData.investigationID, engine: engine, initial: pending())
        let finding = PreviewData.findings[1]
        model.apply(InvestigationEvent(investigationId: model.id, sequence: 1, emittedAt: .now, event: .started(providers: ["codeberg"])))
        #expect(model.status == .running)
        #expect(model.providerStates["codeberg"] == .pending)
        model.apply(InvestigationEvent(investigationId: model.id, sequence: 2, emittedAt: .now, event: .findingDiscovered(finding)))
        model.apply(InvestigationEvent(investigationId: model.id, sequence: 2, emittedAt: .now, event: .findingDiscovered(finding)))
        #expect(model.findings.count == 1, "replayed sequence numbers are ignored")
        model.apply(InvestigationEvent(investigationId: model.id, sequence: 3, emittedAt: .now, event: .finished(status: .cancelled, metrics: PreviewData.metrics)))
        #expect(model.status == .cancelled)
        #expect(model.providerStates["codeberg"] == .cancelled)
        #expect(!model.isRunning)
    }

    @Test func cancelForwardsToEngine() async {
        let engine = ScriptedEngine(investigation: pending(), script: [], detail: PreviewData.detail)
        let model = InvestigationViewModel(id: PreviewData.investigationID, engine: engine, initial: pending())
        await model.cancel()
        #expect(engine.cancelled)
    }

    @Test func appModelStartNavigatesToInvestigation() async throws {
        let engine = ScriptedEngine(investigation: pending(), script: [.finished(status: .completed, metrics: PreviewData.metrics)], detail: PreviewData.detail)
        let app = AppModel(engine: engine)
        try await app.start(StartInvestigationRequest(targetType: .username, value: "exampleuser", purpose: "Authorized test run", providerIds: nil, defaultRegion: nil))
        #expect(app.selection == .investigations)
        #expect(app.investigationPath == [PreviewData.investigationID])
        #expect(app.investigations.count == 1)
    }

    private func waitUntil(timeout: Duration = .seconds(3), _ condition: () -> Bool) async throws {
        let deadline = ContinuousClock.now + timeout
        while !condition() {
            if ContinuousClock.now > deadline {
                Issue.record("condition not met in time")
                return
            }
            try await Task.sleep(for: .milliseconds(10))
        }
    }
}

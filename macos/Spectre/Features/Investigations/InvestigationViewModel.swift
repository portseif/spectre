import Foundation
import Observation

enum ProviderRunState: Equatable, Sendable {
    case pending
    case running
    case completed(findings: UInt32, latencyMs: UInt64)
    case failed(code: EngineErrorCode, message: String)
    case cancelled
}

/// Live state of one investigation: initial load, incremental event
/// streaming, cancellation, and investigator decisions.
@MainActor
@Observable
final class InvestigationViewModel: Identifiable {
    enum Phase: Equatable {
        case idle
        case loading
        case streaming
        case loaded
        case failed(String)
    }

    let id: UUID
    private let engine: any EngineClient
    private let onFinished: @MainActor () -> Void

    private(set) var phase: Phase = .idle
    private(set) var investigation: Investigation?
    private(set) var findings: [Finding] = [] {
        didSet { regroup() }
    }
    private(set) var sections: [FindingSection] = []
    private(set) var graph: IdentityGraph = .empty
    private(set) var providerStates: [String: ProviderRunState] = [:]
    private(set) var progress: Double = 0
    private(set) var actionError: String?
    @ObservationIgnored private var streamTask: Task<Void, Never>?
    @ObservationIgnored private var lastSequence: UInt64 = 0

    init(id: UUID, engine: any EngineClient, initial: Investigation?, onFinished: @escaping @MainActor () -> Void = {}) {
        self.id = id
        self.engine = engine
        self.investigation = initial
        self.onFinished = onFinished
        if let initial { progress = initial.progress }
    }

    var status: InvestigationStatus { investigation?.status ?? .pending }
    var isRunning: Bool { !status.isTerminal }

    /// Called right after `investigation.start`: stream immediately.
    func begin(with investigation: Investigation) {
        self.investigation = investigation
        providerStates = Dictionary(uniqueKeysWithValues: investigation.providers.map { ($0, .pending) })
        attach()
    }

    func load() async {
        guard phase != .streaming else { return }
        if phase == .idle { phase = .loading }
        do {
            let detail = try await engine.investigation(id)
            apply(detail: detail)
            if detail.investigation.status.isTerminal {
                phase = .loaded
            } else {
                attach()
            }
        } catch {
            phase = .failed(error.localizedDescription)
        }
    }

    func reload() async {
        do {
            apply(detail: try await engine.investigation(id))
        } catch {
            actionError = error.localizedDescription
        }
    }

    private func apply(detail: InvestigationDetail) {
        investigation = detail.investigation
        findings = detail.findings
        graph = detail.graph
        progress = detail.investigation.progress
        if providerStates.isEmpty || detail.investigation.status.isTerminal {
            var states: [String: ProviderRunState] = [:]
            for provider in detail.investigation.providers {
                if let failure = detail.investigation.errors.first(where: { $0.providerId == provider }) {
                    states[provider] = .failed(code: failure.code, message: failure.message)
                } else if let latency = detail.investigation.metrics?.providerLatencies.first(where: { $0.providerId == provider }) {
                    states[provider] = latency.outcome == .cancelled ? .cancelled : .completed(findings: latency.findings, latencyMs: latency.latencyMs)
                } else {
                    states[provider] = detail.investigation.status.isTerminal ? .cancelled : .pending
                }
            }
            providerStates = states
        }
    }

    /// Subscribe to the engine's event stream.
    func attach() {
        guard streamTask == nil else { return }
        phase = .streaming
        let stream = engine.events(for: id)
        streamTask = Task { [weak self] in
            do {
                for try await event in stream {
                    self?.apply(event)
                }
            } catch {
                self?.actionError = error.localizedDescription
            }
            await self?.streamEnded()
        }
    }

    func detach() {
        streamTask?.cancel()
        streamTask = nil
    }

    private func streamEnded() async {
        streamTask = nil
        await reload()
        phase = .loaded
        onFinished()
    }

    /// Pure state transition for one engine event.
    func apply(_ event: InvestigationEvent) {
        guard event.sequence > lastSequence else { return }
        lastSequence = event.sequence
        switch event.event {
        case .started(let providers):
            investigation?.status = .running
            for provider in providers where providerStates[provider] == nil {
                providerStates[provider] = .pending
            }
        case .providerStarted(let providerID):
            providerStates[providerID] = .running
        case .findingDiscovered(let finding):
            if !findings.contains(where: { $0.id == finding.id }) {
                findings.append(finding)
            }
        case .providerCompleted(let providerID, let count, let latency):
            providerStates[providerID] = .completed(findings: count, latencyMs: latency)
        case .providerFailed(let failure):
            providerStates[failure.providerId] = .failed(code: failure.code, message: failure.message)
        case .progress(let value):
            progress = value
            investigation?.progress = value
        case .correlationUpdated:
            break
        case .finished(let status, _):
            investigation?.status = status
            progress = 1
            for (provider, state) in providerStates where state == .pending || state == .running {
                providerStates[provider] = .cancelled
            }
        }
    }

    func cancel() async {
        do {
            try await engine.cancelInvestigation(id)
        } catch {
            actionError = error.localizedDescription
        }
    }

    func decide(_ relationshipID: UUID, decision: InvestigatorDecision?) async {
        do {
            graph = try await engine.decide(relationship: relationshipID, decision: decision)
            await reload()
        } catch {
            actionError = error.localizedDescription
        }
    }

    func dismissError() {
        actionError = nil
    }

    private func regroup() {
        let grouped = Dictionary(grouping: findings, by: \.kind)
        sections = FindingKind.allCases.compactMap { kind in
            guard let items = grouped[kind], !items.isEmpty else { return nil }
            let sorted = items.sorted { ($0.confidence.category, $0.discoveredAt) > ($1.confidence.category, $1.discoveredAt) }
            return FindingSection(kind: kind, findings: sorted)
        }
    }
}

struct FindingSection: Identifiable, Equatable {
    let kind: FindingKind
    let findings: [Finding]
    var id: FindingKind { kind }
}

import Foundation
import Observation

enum SidebarItem: String, CaseIterable, Identifiable, Hashable {
    case dashboard, newInvestigation, investigations, identities, breaches, securityAudits, reports, settings

    var id: String { rawValue }

    var title: String {
        switch self {
        case .dashboard: "Dashboard"
        case .newInvestigation: "New Investigation"
        case .investigations: "Investigations"
        case .identities: "Identities"
        case .breaches: "Breach Intelligence"
        case .securityAudits: "Security Audits"
        case .reports: "Reports"
        case .settings: "Settings"
        }
    }

    var symbol: String {
        switch self {
        case .dashboard: "square.grid.2x2"
        case .newInvestigation: "plus.magnifyingglass"
        case .investigations: "list.bullet.rectangle"
        case .identities: "point.3.connected.trianglepath.dotted"
        case .breaches: "exclamationmark.shield"
        case .securityAudits: "lock.shield"
        case .reports: "doc.richtext"
        case .settings: "gearshape"
        }
    }
}

/// What the right-hand inspector shows.
enum InspectorItem: Hashable {
    case finding(Finding)
    case relationship(IdentityRelationship, source: Identity?, target: Identity?)
    case identity(Identity)
    case breach(BreachIncident)
}

/// Root application state, owned by the app and shared through the environment.
@MainActor
@Observable
final class AppModel {
    enum Phase: Equatable {
        case starting
        case ready
        case failed(String)
    }

    private(set) var phase: Phase = .starting
    private(set) var engine: (any EngineClient)?
    var selection: SidebarItem? = .dashboard
    var investigationPath: [UUID] = []
    var inspector: InspectorItem?
    var isInspectorPresented = true
    private(set) var investigations: [Investigation] = []
    private(set) var listError: String?
    var searchText = ""
    @ObservationIgnored private var sessions: [UUID: InvestigationViewModel] = [:]

    init() {}

    /// Inject an engine directly (tests, previews).
    init(engine: any EngineClient) {
        self.engine = engine
        phase = .ready
    }

    static var databaseURL: URL {
        URL.applicationSupportDirectory.appending(path: "Spectre", directoryHint: .isDirectory).appending(path: "spectre.sqlite")
    }

    func bootstrap() async {
        guard engine == nil else { return }
        do {
            let databaseURL = Self.databaseURL
            let engine = try await Task.detached(priority: .userInitiated) { try RustEngine(databaseURL: databaseURL) }.value
            self.engine = engine
            await loadCredentials(into: engine)
            phase = .ready
            AppLog.engine.info("Engine \(RustEngine.version, privacy: .public) started")
            await refreshInvestigations()
        } catch {
            AppLog.engine.error("Engine failed to start: \(error.localizedDescription, privacy: .public)")
            phase = .failed(error.localizedDescription)
        }
    }

    private func loadCredentials(into engine: any EngineClient) async {
        for credential in CredentialID.allCases {
            do {
                if let secret = try KeychainStore.credentials.read(account: credential.rawValue) {
                    try await engine.setCredential(id: credential.rawValue, secret: secret)
                }
            } catch {
                AppLog.engine.error("Could not load credential \(credential.rawValue, privacy: .public): \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    func refreshInvestigations() async {
        guard let engine else { return }
        do {
            investigations = try await engine.investigations(search: searchText.isEmpty ? nil : searchText)
            listError = nil
        } catch {
            listError = error.localizedDescription
        }
    }

    /// The persisted view model for an investigation (created on first use).
    func session(for id: UUID) -> InvestigationViewModel? {
        guard let engine else { return nil }
        if let existing = sessions[id] { return existing }
        let session = InvestigationViewModel(id: id, engine: engine, initial: investigations.first { $0.id == id }) { [weak self] in
            Task { await self?.refreshInvestigations() }
        }
        sessions[id] = session
        return session
    }

    func start(_ request: StartInvestigationRequest) async throws {
        guard let engine else { throw EngineError(code: .internal, message: "Engine is not ready.") }
        let investigation = try await engine.startInvestigation(request)
        await refreshInvestigations()
        let session = session(for: investigation.id)
        session?.begin(with: investigation)
        open(investigation.id)
    }

    func open(_ investigationID: UUID) {
        selection = .investigations
        investigationPath = [investigationID]
    }

    func delete(_ investigationID: UUID) async throws {
        guard let engine else { return }
        try await engine.deleteInvestigation(investigationID)
        sessions[investigationID]?.detach()
        sessions[investigationID] = nil
        investigationPath.removeAll { $0 == investigationID }
        if case .finding(let finding) = inspector, finding.investigationId == investigationID { inspector = nil }
        await refreshInvestigations()
    }

    func credentialsChanged(_ credential: CredentialID, secret: String?) async throws {
        guard let engine else { return }
        if let secret, !secret.isEmpty {
            try KeychainStore.credentials.save(secret, account: credential.rawValue)
            try await engine.setCredential(id: credential.rawValue, secret: secret)
        } else {
            try KeychainStore.credentials.delete(account: credential.rawValue)
            try await engine.clearCredential(id: credential.rawValue)
        }
    }
}

import Foundation

struct EngineError: LocalizedError, Equatable, Sendable {
    let code: EngineErrorCode
    let message: String

    var errorDescription: String? { message }

    static func unsupported(_ operation: String = #function) -> EngineError {
        EngineError(code: .internal, message: "\(operation) is not available")
    }
}

struct StartInvestigationRequest: Encodable, Sendable {
    let targetType: TargetType
    let value: String
    let purpose: String
    let providerIds: [String]?
    let defaultRegion: String?
}

/// Everything the UI asks of the engine. `RustEngine` implements it over the
/// C ABI; tests substitute lightweight mocks.
protocol EngineClient: Sendable {
    func validateTarget(_ type: TargetType, value: String, region: String?) async throws -> TargetValidation
    func startInvestigation(_ request: StartInvestigationRequest) async throws -> Investigation
    func cancelInvestigation(_ id: UUID) async throws
    func investigation(_ id: UUID) async throws -> InvestigationDetail
    func investigations(search: String?) async throws -> [Investigation]
    func deleteInvestigation(_ id: UUID) async throws
    func events(for id: UUID) -> AsyncThrowingStream<InvestigationEvent, any Error>
    func decide(relationship: UUID, decision: InvestigatorDecision?) async throws -> IdentityGraph
    func followUps(_ id: UUID) async throws -> [FollowUp]

    func dashboard() async throws -> DashboardStats
    func providers() async throws -> ProviderListing
    func updateProvider(id: String, enabled: Bool, rateLimitPerMinute: UInt32?) async throws -> ProviderStatus
    func settings() async throws -> EngineSettings
    func updateSettings(_ settings: EngineSettings) async throws -> EngineSettings
    func setCredential(id: String, secret: String) async throws
    func clearCredential(id: String) async throws

    func verifications() async throws -> VerificationList
    func attestEmail(_ email: String, statement: String) async throws -> EmailRecord
    func revokeEmail(_ email: String) async throws -> EmailRecord
    func lookupBreaches(email: String, investigationID: UUID?) async throws -> BreachExposureReport
    func storedExposures(email: String) async throws -> BreachExposureReport
    func refreshBreachCatalog() async throws -> Int
    func searchBreachCatalog(query: String?, limit: Int) async throws -> CatalogSearchResult

    func checkPassword(_ password: String) async throws -> PasswordCheckResult
    func hashInventory(_ text: String) async throws -> HashInventory

    func exportJSON(_ id: UUID) async throws -> Data
    func exportCSV(_ id: UUID) async throws -> String
    func importBundle(_ data: Data) async throws -> UUID
    func auditEvents(limit: Int) async throws -> [AuditEvent]
    func diagnostics() async throws -> Diagnostics
    func purge(olderThanDays: Int) async throws -> Int
    func backup(to url: URL) async throws
    func restore(from url: URL) async throws
    func vacuum() async throws
    func integrityCheck() async throws -> [String]
}

/// Defaults for test doubles: anything not overridden fails loudly.
extension EngineClient {
    func validateTarget(_ type: TargetType, value: String, region: String?) async throws -> TargetValidation { throw EngineError.unsupported() }
    func startInvestigation(_ request: StartInvestigationRequest) async throws -> Investigation { throw EngineError.unsupported() }
    func cancelInvestigation(_ id: UUID) async throws { throw EngineError.unsupported() }
    func investigation(_ id: UUID) async throws -> InvestigationDetail { throw EngineError.unsupported() }
    func investigations(search: String?) async throws -> [Investigation] { [] }
    func deleteInvestigation(_ id: UUID) async throws { throw EngineError.unsupported() }
    func events(for id: UUID) -> AsyncThrowingStream<InvestigationEvent, any Error> { AsyncThrowingStream { $0.finish() } }
    func decide(relationship: UUID, decision: InvestigatorDecision?) async throws -> IdentityGraph { throw EngineError.unsupported() }
    func followUps(_ id: UUID) async throws -> [FollowUp] { [] }
    func dashboard() async throws -> DashboardStats { throw EngineError.unsupported() }
    func providers() async throws -> ProviderListing { ProviderListing(providers: [], services: []) }
    func updateProvider(id: String, enabled: Bool, rateLimitPerMinute: UInt32?) async throws -> ProviderStatus { throw EngineError.unsupported() }
    func settings() async throws -> EngineSettings { .defaults }
    func updateSettings(_ settings: EngineSettings) async throws -> EngineSettings { settings }
    func setCredential(id: String, secret: String) async throws {}
    func clearCredential(id: String) async throws {}
    func verifications() async throws -> VerificationList { VerificationList(emails: []) }
    func attestEmail(_ email: String, statement: String) async throws -> EmailRecord { throw EngineError.unsupported() }
    func revokeEmail(_ email: String) async throws -> EmailRecord { throw EngineError.unsupported() }
    func lookupBreaches(email: String, investigationID: UUID?) async throws -> BreachExposureReport { throw EngineError.unsupported() }
    func storedExposures(email: String) async throws -> BreachExposureReport { throw EngineError.unsupported() }
    func refreshBreachCatalog() async throws -> Int { throw EngineError.unsupported() }
    func searchBreachCatalog(query: String?, limit: Int) async throws -> CatalogSearchResult { CatalogSearchResult(total: 0, breaches: []) }
    func checkPassword(_ password: String) async throws -> PasswordCheckResult { throw EngineError.unsupported() }
    func hashInventory(_ text: String) async throws -> HashInventory { throw EngineError.unsupported() }
    func exportJSON(_ id: UUID) async throws -> Data { throw EngineError.unsupported() }
    func exportCSV(_ id: UUID) async throws -> String { throw EngineError.unsupported() }
    func importBundle(_ data: Data) async throws -> UUID { throw EngineError.unsupported() }
    func auditEvents(limit: Int) async throws -> [AuditEvent] { [] }
    func diagnostics() async throws -> Diagnostics { throw EngineError.unsupported() }
    func purge(olderThanDays: Int) async throws -> Int { 0 }
    func backup(to url: URL) async throws { throw EngineError.unsupported() }
    func restore(from url: URL) async throws { throw EngineError.unsupported() }
    func vacuum() async throws {}
    func integrityCheck() async throws -> [String] { ["ok"] }
}

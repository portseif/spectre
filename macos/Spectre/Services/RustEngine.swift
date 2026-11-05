import Foundation
import SpectreFFI

/// `EngineClient` backed by the Rust engine through its C ABI.
///
/// Every FFI call blocks, so calls run on a private concurrent queue and are
/// bridged to async/await with continuations; nothing touches the main actor.
final class RustEngine: EngineClient, Sendable {
    /// The Rust engine is `Send + Sync`; the handle itself never changes.
    private struct Handle: @unchecked Sendable {
        let pointer: OpaquePointer
    }

    private let handle: Handle
    private let queue = DispatchQueue(label: "io.portseif.spectre.engine", qos: .userInitiated, attributes: .concurrent)
    let databaseURL: URL?

    static var version: String { String(cString: spectre_version()) }

    init(databaseURL: URL?) throws {
        self.databaseURL = databaseURL
        var options: [String: String] = [:]
        if let databaseURL { options["database_path"] = databaseURL.path(percentEncoded: false) }
        let json = String(decoding: try JSONSerialization.data(withJSONObject: options), as: UTF8.self)
        var errorPointer: UnsafeMutablePointer<CChar>?
        guard let pointer = json.withCString({ spectre_engine_open($0, &errorPointer) }) else {
            throw Self.error(fromEnvelope: Self.consume(errorPointer)) ?? EngineError(code: .internal, message: "The engine could not be started.")
        }
        handle = Handle(pointer: pointer)
    }

    deinit {
        spectre_engine_close(handle.pointer)
    }

    // MARK: - FFI plumbing

    private static func consume(_ pointer: UnsafeMutablePointer<CChar>?) -> Data {
        guard let pointer else { return Data() }
        defer { spectre_string_free(pointer) }
        return Data(bytes: pointer, count: strlen(pointer))
    }

    private struct ErrorPayload: Decodable { let code: EngineErrorCode; let message: String }
    private struct ErrorEnvelope: Decodable { let error: ErrorPayload? }
    private struct Envelope<Value: Decodable>: Decodable { let ok: Value }

    private static func error(fromEnvelope data: Data) -> EngineError? {
        guard let payload = try? EngineCoding.decoder().decode(ErrorEnvelope.self, from: data).error else { return nil }
        return EngineError(code: payload.code, message: payload.message)
    }

    /// Runs a blocking FFI function off the caller's executor and returns the raw envelope.
    private func perform(_ body: @escaping @Sendable (OpaquePointer) -> UnsafeMutablePointer<CChar>?) async throws -> Data {
        let handle = handle
        let data: Data = await withCheckedContinuation { continuation in
            queue.async { continuation.resume(returning: Self.consume(body(handle.pointer))) }
        }
        if let error = Self.error(fromEnvelope: data) { throw error }
        return data
    }

    private func rawCall(_ method: String, json: String) async throws -> Data {
        try await perform { pointer in
            method.withCString { methodPointer in json.withCString { spectre_engine_call(pointer, methodPointer, $0) } }
        }
    }

    private func call<Value: Decodable>(_ method: String, _ parameters: [String: JSONValue] = [:], as type: Value.Type = Value.self) async throws -> Value {
        let json = String(decoding: try EngineCoding.encoder().encode(parameters), as: UTF8.self)
        return try decode(try await rawCall(method, json: json))
    }

    private func call<Value: Decodable>(_ method: String, encodable: some Encodable, as type: Value.Type = Value.self) async throws -> Value {
        let json = String(decoding: try EngineCoding.encoder().encode(encodable), as: UTF8.self)
        return try decode(try await rawCall(method, json: json))
    }

    private func decode<Value: Decodable>(_ data: Data) throws -> Value {
        do {
            return try EngineCoding.decoder().decode(Envelope<Value>.self, from: data).ok
        } catch {
            throw EngineError(code: .internal, message: "Unexpected engine response: \(error.localizedDescription)")
        }
    }

    /// The `ok` payload as pretty-printed JSON with the engine's original keys.
    private func rawOK(_ data: Data) throws -> Data {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], let value = object["ok"] else {
            throw EngineError(code: .internal, message: "Unexpected engine response.")
        }
        return try JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
    }

    private static func id(_ uuid: UUID) -> JSONValue { .string(uuid.uuidString.lowercased()) }

    private struct Empty: Decodable {}

    // MARK: - Investigations

    func validateTarget(_ type: TargetType, value: String, region: String?) async throws -> TargetValidation {
        var parameters: [String: JSONValue] = ["target_type": .string(type.rawValue), "value": .string(value)]
        if let region, !region.isEmpty { parameters["default_region"] = .string(region) }
        return try await call("target.validate", parameters)
    }

    func startInvestigation(_ request: StartInvestigationRequest) async throws -> Investigation {
        try await call("investigation.start", encodable: request)
    }

    func cancelInvestigation(_ id: UUID) async throws {
        let _: JSONValue = try await call("investigation.cancel", ["id": Self.id(id)])
    }

    func investigation(_ id: UUID) async throws -> InvestigationDetail {
        try await call("investigation.get", ["id": Self.id(id)])
    }

    func investigations(search: String?) async throws -> [Investigation] {
        var parameters: [String: JSONValue] = ["limit": .number(500)]
        if let search, !search.isEmpty { parameters["search"] = .string(search) }
        return try await call("investigation.list", parameters)
    }

    func deleteInvestigation(_ id: UUID) async throws {
        let _: JSONValue = try await call("investigation.delete", ["id": Self.id(id)])
    }

    func events(for id: UUID) -> AsyncThrowingStream<InvestigationEvent, any Error> {
        let handle = handle
        let queue = queue
        return AsyncThrowingStream { continuation in
            let stop = StopFlag()
            continuation.onTermination = { _ in stop.stop() }
            queue.async {
                let decoder = EngineCoding.decoder()
                let identifier = id.uuidString.lowercased()
                while !stop.isStopped {
                    let data = Self.consume(identifier.withCString { spectre_engine_poll_events(handle.pointer, $0, 128, 250) })
                    if let error = Self.error(fromEnvelope: data) {
                        continuation.finish(throwing: error)
                        return
                    }
                    do {
                        let batch = try decoder.decode(Envelope<EventBatch>.self, from: data).ok
                        for event in batch.events { continuation.yield(event) }
                        if batch.finished {
                            continuation.finish()
                            return
                        }
                    } catch {
                        continuation.finish(throwing: error)
                        return
                    }
                }
            }
        }
    }

    func decide(relationship: UUID, decision: InvestigatorDecision?) async throws -> IdentityGraph {
        try await call("relationship.decide", ["relationship_id": Self.id(relationship), "decision": decision.map { .string($0.rawValue) } ?? .null])
    }

    func followUps(_ id: UUID) async throws -> [FollowUp] {
        try await call("investigation.suggestions", ["id": Self.id(id)])
    }

    // MARK: - Settings & providers

    func dashboard() async throws -> DashboardStats { try await call("dashboard.stats") }

    func providers() async throws -> ProviderListing { try await call("providers.list") }

    func updateProvider(id: String, enabled: Bool, rateLimitPerMinute: UInt32?) async throws -> ProviderStatus {
        try await call("providers.update", [
            "provider_id": .string(id),
            "enabled": .bool(enabled),
            "rate_limit_per_minute": rateLimitPerMinute.map { .number(Double($0)) } ?? .null,
        ])
    }

    func settings() async throws -> EngineSettings { try await call("settings.get") }

    func updateSettings(_ settings: EngineSettings) async throws -> EngineSettings {
        try await call("settings.update", encodable: settings)
    }

    func setCredential(id: String, secret: String) async throws {
        let _: JSONValue = try await call("credentials.set", ["credential_id": .string(id), "secret": .string(secret)])
    }

    func clearCredential(id: String) async throws {
        let _: JSONValue = try await call("credentials.clear", ["credential_id": .string(id)])
    }

    // MARK: - Verification & breaches

    func verifications() async throws -> VerificationList { try await call("verification.list") }

    func attestEmail(_ email: String, statement: String) async throws -> EmailRecord {
        try await call("verification.email.attest", ["email": .string(email), "statement": .string(statement)])
    }

    func revokeEmail(_ email: String) async throws -> EmailRecord {
        try await call("verification.email.revoke", ["email": .string(email)])
    }

    func startDomainVerification(_ domain: String) async throws -> DomainRecord {
        try await call("verification.domain.start", ["domain": .string(domain)])
    }

    func checkDomainVerification(_ domain: String) async throws -> DomainCheckResult {
        try await call("verification.domain.check", ["domain": .string(domain)])
    }

    func lookupBreaches(email: String, investigationID: UUID?) async throws -> BreachExposureReport {
        try await call("breach.lookup", ["email": .string(email), "investigation_id": investigationID.map(Self.id) ?? .null])
    }

    func storedExposures(email: String) async throws -> BreachExposureReport {
        try await call("breach.exposures", ["email": .string(email)])
    }

    func refreshBreachCatalog() async throws -> Int {
        struct Refreshed: Decodable { let breaches: Int }
        return try await call("breach.catalog.refresh", as: Refreshed.self).breaches
    }

    func searchBreachCatalog(query: String?, limit: Int) async throws -> CatalogSearchResult {
        try await call("breach.catalog.search", ["query": query.map { .string($0) } ?? .null, "limit": .number(Double(limit))])
    }

    // MARK: - Security auditing

    /// The password crosses the FFI as raw bytes (never JSON) and the local
    /// byte copy is wiped with `memset_s` immediately after the call.
    /// Swift `String` storage itself cannot be reliably zeroed.
    func checkPassword(_ password: String) async throws -> PasswordCheckResult {
        let data = try await perform { pointer in
            var bytes = Array(password.utf8)
            defer {
                bytes.withUnsafeMutableBytes { buffer in
                    if let base = buffer.baseAddress { _ = memset_s(base, buffer.count, 0, buffer.count) }
                }
            }
            return bytes.withUnsafeBufferPointer { spectre_check_password(pointer, $0.baseAddress, $0.count) }
        }
        return try decode(data)
    }

    func hashInventory(_ text: String) async throws -> HashInventory {
        try await call("audit.hash_inventory", ["text": .string(text)])
    }

    // MARK: - Export, maintenance

    func exportJSON(_ id: UUID) async throws -> Data {
        try rawOK(try await rawCall("investigation.export_json", json: #"{"id":"\#(id.uuidString.lowercased())"}"#))
    }

    func exportCSV(_ id: UUID) async throws -> String {
        struct CSV: Decodable { let csv: String }
        return try await call("investigation.export_csv", ["id": Self.id(id)], as: CSV.self).csv
    }

    func importBundle(_ data: Data) async throws -> UUID {
        guard (try? JSONSerialization.jsonObject(with: data)) is [String: Any] else {
            throw EngineError(code: .invalidInput, message: "The file is not a Spectre investigation export.")
        }
        struct Imported: Decodable { let id: UUID }
        let json = #"{"bundle":"# + String(decoding: data, as: UTF8.self) + "}"
        let imported: Imported = try decode(try await rawCall("investigation.import", json: json))
        return imported.id
    }

    func auditEvents(limit: Int) async throws -> [AuditEvent] {
        try await call("audit.events", ["limit": .number(Double(limit))])
    }

    func diagnostics() async throws -> Diagnostics { try await call("engine.diagnostics") }

    func purge(olderThanDays: Int) async throws -> Int {
        struct Purged: Decodable { let purged: Int }
        return try await call("privacy.purge", ["older_than_days": .number(Double(olderThanDays))], as: Purged.self).purged
    }

    func backup(to url: URL) async throws {
        let _: JSONValue = try await call("storage.backup", ["path": .string(url.path(percentEncoded: false))])
    }

    func restore(from url: URL) async throws {
        let _: JSONValue = try await call("storage.restore", ["path": .string(url.path(percentEncoded: false))])
    }

    func vacuum() async throws {
        let _: JSONValue = try await call("storage.vacuum")
    }

    func integrityCheck() async throws -> [String] {
        struct Results: Decodable { let results: [String] }
        return try await call("storage.integrity_check", as: Results.self).results
    }
}

/// Thread-safe one-way flag used to stop event polling.
private final class StopFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var stopped = false

    var isStopped: Bool { lock.withLock { stopped } }

    func stop() { lock.withLock { stopped = true } }
}

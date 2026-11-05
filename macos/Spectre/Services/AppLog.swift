import OSLog

/// Unified logging. Never log identifiers under investigation, passwords,
/// hashes, or credentials; use `privacy: .private` for anything user-derived.
enum AppLog {
    static let engine = Logger(subsystem: "io.portseif.Spectre", category: "engine")
    static let ui = Logger(subsystem: "io.portseif.Spectre", category: "ui")
    static let reports = Logger(subsystem: "io.portseif.Spectre", category: "reports")
}

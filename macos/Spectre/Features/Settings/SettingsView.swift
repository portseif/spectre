import SwiftUI
import UniformTypeIdentifiers

enum AppearancePreference: String, CaseIterable, Identifiable {
    case system, dark, light
    var id: String { rawValue }
    var label: String { rawValue.capitalized }
    var colorScheme: ColorScheme? {
        switch self {
        case .system: nil
        case .dark: .dark
        case .light: .light
        }
    }
}

struct SettingsView: View {
    var body: some View {
        TabView {
            Tab("General", systemImage: "gearshape") { GeneralSettings() }
            Tab("Providers", systemImage: "server.rack") { ProviderSettings() }
            Tab("Performance", systemImage: "speedometer") { PerformanceSettings() }
            Tab("Privacy", systemImage: "hand.raised") { PrivacySettings() }
            Tab("Advanced", systemImage: "wrench.and.screwdriver") { AdvancedSettings() }
        }
        .scenePadding()
        .navigationTitle("Settings")
    }
}

// MARK: - General

private struct GeneralSettings: View {
    @AppStorage("appearance") private var appearance: AppearancePreference = .system
    @AppStorage("defaultTargetType") private var defaultTargetType: TargetType = .username

    var body: some View {
        Form {
            Picker("Appearance", selection: $appearance) {
                ForEach(AppearancePreference.allCases) { Text($0.label).tag($0) }
            }
            Picker("Default search type", selection: $defaultTargetType) {
                ForEach(TargetType.allCases) { Label($0.label, systemImage: $0.symbol).tag($0) }
            }
            Section("Investigation storage") {
                LabeledContent("Database") {
                    Text(AppModel.databaseURL.path(percentEncoded: false)).textSelection(.enabled).font(.caption.monospaced())
                }
                Button("Reveal in Finder") { NSWorkspace.shared.activateFileViewerSelecting([AppModel.databaseURL]) }
                Text("Investigations are stored in Spectre's sandboxed container. Use Advanced > Back Up to copy the database elsewhere.")
                    .font(.caption)
                    .foregroundStyle(.spectreSecondary)
            }
        }
        .formStyle(.grouped)
    }
}

// MARK: - Providers

private struct ProviderSettings: View {
    @Environment(AppModel.self) private var model
    @State private var listing = ProviderListing(providers: [], services: [])
    @State private var errorMessage: String?

    var body: some View {
        Form {
            Section {
                ForEach(CredentialID.allCases) { credential in
                    CredentialEditor(credential: credential, isConfigured: isConfigured(credential)) { secret in
                        do {
                            try await model.credentialsChanged(credential, secret: secret)
                            await reload()
                        } catch {
                            errorMessage = error.localizedDescription
                        }
                    }
                }
            } header: {
                Text("API credentials")
            } footer: {
                Text("Stored only in your Keychain and passed to the engine in memory. Never written to the database, logs, or exports.")
            }
            Section("Breach & password services") {
                ForEach(listing.services) { service in
                    VStack(alignment: .leading, spacing: 2) {
                        HStack {
                            Text(service.name)
                            Spacer()
                            if service.credentialRequired {
                                TagChip(text: service.credentialConfigured ? "Key configured" : "Key required", tint: service.credentialConfigured ? Theme.success : Theme.warning)
                            } else {
                                TagChip(text: "No key needed", tint: Theme.success)
                            }
                        }
                        Text(service.description).font(.caption).foregroundStyle(.spectreSecondary)
                    }
                }
            }
            Section("Discovery providers") {
                ForEach(listing.providers) { provider in
                    ProviderRow(provider: provider) { enabled, limit in
                        await update(provider.id, enabled: enabled, limit: limit)
                    }
                }
            }
            if let errorMessage {
                Label(errorMessage, systemImage: "exclamationmark.triangle.fill").foregroundStyle(Theme.danger)
            }
        }
        .formStyle(.grouped)
        .task { await reload() }
    }

    private func isConfigured(_ credential: CredentialID) -> Bool {
        listing.services.contains { $0.credentialId == credential.rawValue && $0.credentialConfigured }
            || listing.providers.contains { $0.credential.credentialId == credential.rawValue && $0.credentialConfigured }
    }

    private func reload() async {
        guard let engine = model.engine else { return }
        do { listing = try await engine.providers() } catch { errorMessage = error.localizedDescription }
    }

    private func update(_ providerID: String, enabled: Bool, limit: UInt32) async {
        guard let engine = model.engine else { return }
        do {
            _ = try await engine.updateProvider(id: providerID, enabled: enabled, rateLimitPerMinute: limit)
            await reload()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

private struct CredentialEditor: View {
    let credential: CredentialID
    let isConfigured: Bool
    let onSave: (String?) async -> Void
    @State private var secret = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(credential.title)
                Spacer()
                TagChip(text: isConfigured ? "Configured" : "Not set", tint: isConfigured ? Theme.success : Theme.secondaryText)
            }
            HStack {
                SecureField("Paste key", text: $secret)
                Button("Save") {
                    let value = secret
                    secret = ""
                    Task { await onSave(value) }
                }
                .disabled(secret.isEmpty)
                Button("Remove", role: .destructive) { Task { await onSave(nil) } }
                    .disabled(!isConfigured)
            }
            Text(credential.help).font(.caption).foregroundStyle(.spectreSecondary)
        }
    }
}

private struct ProviderRow: View {
    let provider: ProviderStatus
    let onChange: (Bool, UInt32) async -> Void
    @State private var enabled = true
    @State private var limit: UInt32 = 30

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Toggle(isOn: $enabled) {
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(provider.name)
                        ForEach(provider.supportedTargets, id: \.self) { TagChip(text: $0.label) }
                    }
                    Text(provider.description).font(.caption).foregroundStyle(.spectreSecondary)
                    Text(provider.allowedHosts.isEmpty ? (provider.usesNetwork ? "Contacts the investigated domain only (public IPs, HTTPS)" : "Offline") : "Hosts: \(provider.allowedHosts.joined(separator: ", "))")
                        .font(.caption2)
                        .foregroundStyle(.spectreSecondary)
                }
            }
            Stepper("Rate limit: \(limit) requests/min", value: $limit, in: 1...600, step: limit < 10 ? 1 : 5)
                .font(.caption)
                .disabled(!enabled)
        }
        .onAppear {
            enabled = provider.enabled
            limit = provider.rateLimitPerMinute
        }
        .onChange(of: enabled) { _, newValue in
            guard newValue != provider.enabled else { return }
            Task { await onChange(newValue, limit) }
        }
        .onChange(of: limit) { _, newValue in
            guard newValue != provider.rateLimitPerMinute else { return }
            Task { await onChange(enabled, newValue) }
        }
    }
}

// MARK: - Performance

private struct PerformanceSettings: View {
    @Environment(AppModel.self) private var model
    @State private var settings = EngineSettings.defaults
    @State private var saved = EngineSettings.defaults
    @State private var message: String?

    var body: some View {
        Form {
            Section {
                Stepper("Maximum concurrency: \(settings.maxConcurrency)", value: $settings.maxConcurrency, in: 1...32)
                Stepper("Request timeout: \(settings.requestTimeoutSecs) s", value: $settings.requestTimeoutSecs, in: 2...120)
                Stepper("Provider deadline: \(settings.providerTimeoutSecs) s", value: $settings.providerTimeoutSecs, in: 5...600, step: 5)
            } header: {
                Text("Concurrency & timeouts")
            } footer: {
                Text("Concurrency is a global cap across all running investigations. Conservative values respect provider rate limits.")
            }
            Section("Caching & retries") {
                Stepper("Cache duration: \(settings.cacheTtlSecs / 60) min", value: $settings.cacheTtlSecs, in: 0...86_400, step: 60)
                Stepper("Retry limit: \(settings.maxRetries)", value: $settings.maxRetries, in: 0...5)
                Stepper("Backoff base delay: \(settings.retryBaseDelayMs) ms", value: $settings.retryBaseDelayMs, in: 50...10_000, step: 50)
                Stepper("Default rate limit: \(settings.defaultRateLimitPerMinute)/min", value: $settings.defaultRateLimitPerMinute, in: 1...600)
            }
            HStack {
                if let message { Text(message).font(.caption).foregroundStyle(.spectreSecondary) }
                Spacer()
                Button("Restore Defaults") { settings = EngineSettings(
                    maxConcurrency: 4, requestTimeoutSecs: 15, providerTimeoutSecs: 45, cacheTtlSecs: 900, maxRetries: 2,
                    retryBaseDelayMs: 400, defaultRateLimitPerMinute: 30, retentionDays: settings.retentionDays
                ) }
                Button("Save") { Task { await save() } }
                    .buttonStyle(.borderedProminent)
                    .disabled(settings == saved)
            }
        }
        .formStyle(.grouped)
        .task { await load() }
    }

    private func load() async {
        guard let engine = model.engine, let current = try? await engine.settings() else { return }
        settings = current
        saved = current
    }

    private func save() async {
        guard let engine = model.engine else { return }
        do {
            saved = try await engine.updateSettings(settings)
            settings = saved
            message = "Saved"
        } catch {
            message = error.localizedDescription
        }
    }
}

// MARK: - Privacy

private struct PrivacySettings: View {
    @Environment(AppModel.self) private var model
    @State private var settings = EngineSettings.defaults
    @State private var purgeDays = 90
    @State private var confirmDeleteAll = false
    @State private var message: String?

    var body: some View {
        Form {
            Section {
                Picker("Keep investigations", selection: $settings.retentionDays) {
                    Text("Forever").tag(UInt32(0))
                    ForEach([7, 30, 90, 180, 365], id: \.self) { Text("\($0) days").tag(UInt32($0)) }
                }
                .onChange(of: settings.retentionDays) { _, _ in Task { await saveRetention() } }
            } header: {
                Text("Data retention")
            } footer: {
                Text("Older investigations are securely deleted at launch. The audit log records each purge.")
            }
            Section("Investigation deletion") {
                Stepper("Delete investigations older than \(purgeDays) days", value: $purgeDays, in: 1...3650)
                HStack {
                    Button("Delete Older Investigations") { Task { await purge(days: purgeDays) } }
                    Button("Delete All Investigations…", role: .destructive) { confirmDeleteAll = true }
                }
            }
            Section("Exports") {
                Text("Exports (PDF, JSON, CSV) are written only where you choose and are not encrypted. They contain findings, evidence URLs, and the recorded authorization purpose, but never API keys or passwords. CSV cells are neutralized against spreadsheet formula injection.")
                    .font(.callout)
                    .foregroundStyle(.spectreSecondary)
            }
            Section("Local storage protection") {
                Label("App Sandbox container, readable only by your user (file mode 0600)", systemImage: "lock.square")
                Label("SQLite secure delete: removed records are overwritten, and the WAL is checkpointed after deletion", systemImage: "eraser")
                Label("API keys in Keychain only; passwords are never stored", systemImage: "key")
                Label("Turn on FileVault for full-disk encryption at rest", systemImage: "externaldrive.badge.checkmark")
            }
            .font(.callout)
            if let message { Text(message).font(.caption).foregroundStyle(.spectreSecondary) }
        }
        .formStyle(.grouped)
        .task {
            if let engine = model.engine, let current = try? await engine.settings() { settings = current }
        }
        .confirmationDialog("Delete every investigation?", isPresented: $confirmDeleteAll) {
            Button("Delete All", role: .destructive) { Task { await purge(days: 0) } }
        } message: {
            Text("All findings, identities, and relationships are removed. This cannot be undone.")
        }
    }

    private func saveRetention() async {
        guard let engine = model.engine else { return }
        do {
            var updated = try await engine.settings()
            updated.retentionDays = settings.retentionDays
            _ = try await engine.updateSettings(updated)
            message = "Retention saved"
        } catch {
            message = error.localizedDescription
        }
    }

    private func purge(days: Int) async {
        guard let engine = model.engine else { return }
        do {
            let purged = try await engine.purge(olderThanDays: days)
            message = "Deleted \(purged) investigation(s)"
            await model.refreshInvestigations()
        } catch {
            message = error.localizedDescription
        }
    }
}

// MARK: - Advanced

private struct AdvancedSettings: View {
    @Environment(AppModel.self) private var model
    @AppStorage("developerMode") private var developerMode = false
    @State private var diagnostics: Diagnostics?
    @State private var auditEvents: [AuditEvent] = []
    @State private var message: String?
    @State private var isBackingUp = false
    @State private var isRestoring = false
    @State private var confirmRestore: URL?

    var body: some View {
        Form {
            Section("Rust engine diagnostics") {
                if let diagnostics {
                    KeyValueRow(label: "Engine version", value: diagnostics.engineVersion)
                    KeyValueRow(label: "Schema version", value: "\(diagnostics.storage.schemaVersion)")
                    KeyValueRow(label: "Database size", value: ByteCountFormatter.string(fromByteCount: Int64(diagnostics.storage.sizeBytes), countStyle: .file))
                    KeyValueRow(label: "Providers", value: "\(diagnostics.providers)")
                    KeyValueRow(label: "Active investigations", value: "\(diagnostics.activeInvestigations)")
                    KeyValueRow(label: "HTTP requests (session)", value: "\(diagnostics.httpRequests) · \(diagnostics.retries) retries")
                    KeyValueRow(label: "Cache", value: "\(diagnostics.cacheHits) hits / \(diagnostics.cacheMisses) misses · \(diagnostics.cacheEntries) entries")
                    KeyValueRow(label: "Uptime", value: Duration.seconds(diagnostics.uptimeSeconds).formatted(.units(allowed: [.hours, .minutes, .seconds])))
                    DisclosureGroup("Approved endpoints (\(diagnostics.allowedHosts.count))") {
                        Text(diagnostics.allowedHosts.joined(separator: "\n")).font(.caption.monospaced()).textSelection(.enabled)
                    }
                }
                Button("Refresh") { Task { await refresh() } }
            }
            Section("Application logs") {
                Text("Spectre logs to the unified log under subsystem io.portseif.Spectre. Identifiers, passwords, and keys are never logged.")
                    .font(.caption).foregroundStyle(.spectreSecondary)
                HStack {
                    Text("log stream --predicate 'subsystem == \"io.portseif.Spectre\"'").font(.caption.monospaced()).textSelection(.enabled)
                    Spacer()
                    Button("Open Console") { NSWorkspace.shared.open(URL(fileURLWithPath: "/System/Applications/Utilities/Console.app")) }
                }
            }
            Section("Database maintenance") {
                HStack {
                    Button("Check Integrity") { run { "Integrity: " + (try await $0.integrityCheck()).joined(separator: ", ") } }
                    Button("Compact (VACUUM)") { run { try await $0.vacuum(); return "Database compacted" } }
                    Button("Back Up…") { isBackingUp = true }
                    Button("Restore…") { isRestoring = true }
                }
                if let message { Text(message).font(.caption).foregroundStyle(.spectreSecondary) }
            }
            Section("Developer") {
                Toggle("Developer mode (show audit log)", isOn: $developerMode)
                if developerMode {
                    ForEach(auditEvents) { event in
                        VStack(alignment: .leading, spacing: 2) {
                            Text("\(event.eventType.humanizedKey) · \(event.createdAt.formatted(date: .abbreviated, time: .standard))").font(.caption.weight(.medium))
                            Text(event.detail.displayText).font(.caption2).foregroundStyle(.spectreSecondary).lineLimit(3)
                        }
                    }
                }
            }
        }
        .formStyle(.grouped)
        .task(id: developerMode) { await refresh() }
        .fileExporter(isPresented: $isBackingUp, document: ExportDocument(data: Data(), contentType: .data, filename: "spectre-backup.sqlite"), contentType: .data, defaultFilename: "spectre-backup.sqlite") { result in
            // The engine writes the snapshot itself (VACUUM INTO); the empty placeholder is replaced.
            if case .success(let url) = result {
                try? FileManager.default.removeItem(at: url)
                run { try await $0.backup(to: url); return "Backed up to \(url.lastPathComponent)" }
            }
        }
        .fileImporter(isPresented: $isRestoring, allowedContentTypes: [.data, .item]) { result in
            if case .success(let url) = result { confirmRestore = url }
        }
        .confirmationDialog("Replace the current database with this backup?", isPresented: Binding(get: { confirmRestore != nil }, set: { if !$0 { confirmRestore = nil } }), presenting: confirmRestore) { url in
            Button("Restore", role: .destructive) {
                run {
                    let accessing = url.startAccessingSecurityScopedResource()
                    defer { if accessing { url.stopAccessingSecurityScopedResource() } }
                    try await $0.restore(from: url)
                    return "Restored \(url.lastPathComponent)"
                }
            }
        } message: { _ in
            Text("The backup is validated first. Current data is replaced.")
        }
    }

    private func refresh() async {
        guard let engine = model.engine else { return }
        diagnostics = try? await engine.diagnostics()
        if developerMode { auditEvents = (try? await engine.auditEvents(limit: 50)) ?? [] }
    }

    private func run(_ action: @escaping @MainActor (any EngineClient) async throws -> String) {
        guard let engine = model.engine else { return }
        Task {
            do {
                message = try await action(engine)
                await model.refreshInvestigations()
                await refresh()
            } catch {
                message = error.localizedDescription
            }
        }
    }
}

#Preview {
    SettingsView()
        .environment(AppModel(engine: PreviewEngine()))
        .frame(width: 720, height: 560)
}

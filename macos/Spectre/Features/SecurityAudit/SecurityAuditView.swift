import SwiftUI
import UniformTypeIdentifiers

struct SecurityAuditView: View {
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Theme.spacing) {
                PasswordCheckPanel()
                HashInventoryPanel()
            }
            .padding(24)
        }
        .navigationTitle("Security Audits")
    }
}

/// Workflow A: k-anonymity check of a voluntarily supplied password.
private struct PasswordCheckPanel: View {
    @Environment(AppModel.self) private var model
    @State private var password = ""
    @State private var result: PasswordCheckResult?
    @State private var isChecking = false
    @State private var errorMessage: String?

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                SectionHeader(title: "Password exposure check", symbol: "key.viewfinder")
                Text("The password is hashed with SHA-1 on this Mac. Only the first 5 hex characters of the hash are sent to Pwned Passwords (with response padding); the match happens locally. Nothing is stored or logged.")
                    .font(.callout)
                    .foregroundStyle(.spectreSecondary)
                HStack {
                    SecureField("Password to check", text: $password)
                        .textFieldStyle(.roundedBorder)
                        .onSubmit(check)
                    Button(action: check) {
                        if isChecking { ProgressView().controlSize(.small) } else { Text("Check") }
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(Theme.accent)
                    .disabled(password.isEmpty || isChecking)
                }
                if let errorMessage {
                    Label(errorMessage, systemImage: "exclamationmark.triangle.fill").foregroundStyle(Theme.danger)
                }
                if let result {
                    PasswordResultView(compromised: result.compromised, occurrences: result.occurrences, recommendation: result.recommendation, rangeSize: result.rangeSize)
                }
            }
        }
    }

    private func check() {
        guard let engine = model.engine, !password.isEmpty else { return }
        let candidate = password
        password = ""
        isChecking = true
        errorMessage = nil
        Task {
            do {
                result = try await engine.checkPassword(candidate)
            } catch {
                errorMessage = error.localizedDescription
            }
            isChecking = false
        }
    }
}

private struct PasswordResultView: View {
    let compromised: Bool
    let occurrences: UInt64
    let recommendation: String
    let rangeSize: UInt32

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: compromised ? "exclamationmark.octagon.fill" : "checkmark.shield.fill")
                .font(.largeTitle)
                .foregroundStyle(compromised ? Theme.danger : Theme.success)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text(compromised ? "Found in \(occurrences.formatted()) breach records" : "Not found in Pwned Passwords")
                    .font(.headline)
                Text(recommendation).font(.callout)
                Text("Matched locally against \(rangeSize) candidate suffixes.").font(.caption).foregroundStyle(.spectreSecondary)
            }
        }
        .padding(12)
        .background((compromised ? Theme.danger : Theme.success).opacity(0.1), in: .rect(cornerRadius: 8))
        .accessibilityElement(children: .combine)
    }
}

/// Workflow B (initial scope): storage-scheme inventory for authorized admins.
private struct HashInventoryPanel: View {
    @Environment(AppModel.self) private var model
    @State private var isImporting = false
    @State private var authorized = false
    @State private var inventory: HashInventory?
    @State private var sourceName: String?
    @State private var errorMessage: String?

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                SectionHeader(title: "Password-hash storage audit", symbol: "lock.doc")
                Text("For administrators auditing systems they own or are authorized to test. Spectre identifies storage schemes and parameters, flags legacy or unsalted hashing, and recommends migrations. It never attempts to recover passwords, and only aggregate counts are kept.")
                    .font(.callout)
                    .foregroundStyle(.spectreSecondary)
                Toggle("I am authorized to audit the system these hashes come from", isOn: $authorized)
                HStack {
                    Button("Choose Hash Export…") { isImporting = true }
                        .disabled(!authorized)
                    if let sourceName { Text(sourceName).font(.caption).foregroundStyle(.spectreSecondary) }
                }
                Text("Accepted: one hash per line, user:hash, user<TAB>hash, /etc/shadow, or pwdump.").font(.caption).foregroundStyle(.spectreSecondary)
                if let errorMessage {
                    Label(errorMessage, systemImage: "exclamationmark.triangle.fill").foregroundStyle(Theme.danger)
                }
                if let inventory { InventoryResult(inventory: inventory) }
            }
        }
        .fileImporter(isPresented: $isImporting, allowedContentTypes: [.plainText, .text, .data]) { result in
            switch result {
            case .success(let url): analyze(url)
            case .failure(let error): errorMessage = error.localizedDescription
            }
        }
    }

    private func analyze(_ url: URL) {
        guard let engine = model.engine else { return }
        errorMessage = nil
        Task {
            do {
                let accessing = url.startAccessingSecurityScopedResource()
                defer { if accessing { url.stopAccessingSecurityScopedResource() } }
                let text = try String(contentsOf: url, encoding: .utf8)
                inventory = try await engine.hashInventory(text)
                sourceName = url.lastPathComponent
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }
}

private struct InventoryResult: View {
    let inventory: HashInventory

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 20) {
                StatColumn(title: "Hashes", value: inventory.hashesAnalyzed.formatted())
                StatColumn(title: "Unsalted", value: inventory.unsaltedCount.formatted())
                StatColumn(title: "Duplicates", value: inventory.duplicateValues.formatted())
                StatColumn(title: "No password", value: inventory.accountsWithoutPassword.formatted())
                Spacer()
                TagChip(text: "Overall: \(inventory.overall.label)", tint: Theme.color(for: inventory.overall), symbol: "gauge.with.needle")
            }
            Table(inventory.schemes) {
                TableColumn("Scheme") { scheme in Text(scheme.label) }
                TableColumn("Count") { scheme in Text(scheme.count, format: .number).monospacedDigit() }.width(70)
                TableColumn("Salted") { scheme in Text(scheme.salted.map { $0 ? "Yes" : "No" } ?? "?") }.width(60)
                TableColumn("Strength") { scheme in TagChip(text: scheme.strength.label, tint: Theme.color(for: scheme.strength)) }.width(110)
                TableColumn("Parameters") { scheme in
                    Text(scheme.parameters.sorted { $0.key < $1.key }.map { "\($0.key) ×\($0.value)" }.joined(separator: ", "))
                        .foregroundStyle(.spectreSecondary)
                }
            }
            .frame(minHeight: 160)
            ForEach(inventory.recommendations, id: \.self) { Label($0, systemImage: "wrench.and.screwdriver").font(.callout) }
        }
    }
}

private struct StatColumn: View {
    let title: LocalizedStringKey
    let value: String

    var body: some View {
        VStack(alignment: .leading) {
            Text(value).font(.title2.weight(.semibold).monospacedDigit())
            Text(title).font(.caption).foregroundStyle(.spectreSecondary)
        }
        .accessibilityElement(children: .combine)
    }
}

#Preview {
    NavigationStack { SecurityAuditView() }
        .environment(AppModel(engine: PreviewEngine()))
        .frame(width: 820, height: 760)
}

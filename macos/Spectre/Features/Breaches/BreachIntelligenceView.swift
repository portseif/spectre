import Charts
import SwiftUI

struct BreachIntelligenceView: View {
    @State private var pane: Pane = .ownership
    @State private var reportEmail: String?

    enum Pane: String, CaseIterable, Identifiable {
        case ownership = "Ownership"
        case exposure = "Exposure"
        case catalog = "Catalog"
        var id: String { rawValue }
    }

    var body: some View {
        VStack(spacing: 0) {
            Picker("Section", selection: $pane) {
                ForEach(Pane.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .padding(16)
            Divider()
            switch pane {
            case .ownership:
                OwnershipVerificationView { email in
                    reportEmail = email
                    pane = .exposure
                }
            case .exposure: ExposureReportView(email: $reportEmail)
            case .catalog: BreachCatalogView()
            }
        }
        .navigationTitle("Breach Intelligence")
    }
}

// MARK: - Ownership verification

private struct OwnershipVerificationView: View {
    @Environment(AppModel.self) private var model
    let onShowReport: (String) -> Void
    @State private var list = VerificationList(emails: [], domains: [])
    @State private var newDomain = ""
    @State private var attestationTarget: AttestationTarget?
    @State private var domainMessage: String?
    @State private var errorMessage: String?

    var body: some View {
        Form {
            Section {
                if list.emails.isEmpty {
                    Text("Addresses appear here when they are investigated or publicly observed.").foregroundStyle(.spectreSecondary)
                }
                ForEach(list.emails) { record in
                    EmailVerificationRow(record: record) {
                        attestationTarget = AttestationTarget(email: record.email)
                    } onRevoke: {
                        perform { _ = try await $0.revokeEmail(record.email) }
                    } onReport: {
                        onShowReport(record.email)
                    }
                }
                Button("Attest Another Address…") { attestationTarget = AttestationTarget(email: "") }
            } header: {
                Text("Email addresses")
            } footer: {
                Text("Only ownership-verified addresses can be submitted for account-specific breach lookups. Attestation records your statement in the audit log; DNS verification proves control of the whole domain.")
            }

            Section {
                ForEach(list.domains) { record in
                    DomainVerificationRow(record: record) {
                        perform { _ = try await $0.startDomainVerification(record.domain) }
                    } onCheck: {
                        perform { engine in
                            let result = try await engine.checkDomainVerification(record.domain)
                            domainMessage = result.message
                        }
                    }
                }
                HStack {
                    TextField("Domain you control", text: $newDomain, prompt: Text("example.com"))
                    Button("Start DNS Verification") {
                        let domain = newDomain
                        perform { engine in
                            _ = try await engine.startDomainVerification(domain)
                            newDomain = ""
                        }
                    }
                    .disabled(newDomain.isEmpty)
                }
                if let domainMessage {
                    Text(domainMessage).font(.callout).foregroundStyle(.spectreSecondary)
                }
            } header: {
                Text("Domains")
            } footer: {
                Text("Publish the TXT record shown, then check. Every address on a verified domain is treated as ownership-verified.")
            }
            if let errorMessage {
                Label(errorMessage, systemImage: "exclamationmark.triangle.fill").foregroundStyle(Theme.danger)
            }
        }
        .formStyle(.grouped)
        .task { await reload() }
        .sheet(item: $attestationTarget) { target in
            AttestationSheet(initialEmail: target.email) { email, statement in
                perform { _ = try await $0.attestEmail(email, statement: statement) }
            }
        }
    }

    private func reload() async {
        guard let engine = model.engine else { return }
        do {
            list = try await engine.verifications()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func perform(_ action: @escaping @MainActor (any EngineClient) async throws -> Void) {
        guard let engine = model.engine else { return }
        errorMessage = nil
        Task {
            do {
                try await action(engine)
            } catch {
                errorMessage = error.localizedDescription
            }
            await reload()
        }
    }
}

private struct AttestationTarget: Identifiable {
    let email: String
    let id = UUID()
}

private struct EmailVerificationRow: View {
    let record: EmailRecord
    let onAttest: () -> Void
    let onRevoke: () -> Void
    let onReport: () -> Void

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(record.email).font(.body.weight(.medium))
                if let method = record.verificationMethod {
                    Text(method.label + (record.verifiedAt.map { " · \($0.formatted(date: .abbreviated, time: .omitted))" } ?? ""))
                        .font(.caption)
                        .foregroundStyle(.spectreSecondary)
                }
            }
            Spacer()
            VerificationBadge(status: record.verificationStatus)
            if record.verificationStatus == .ownershipVerified {
                Button("Exposure Report", action: onReport)
                if record.verificationMethod == .investigatorAttestation {
                    Button("Revoke", role: .destructive, action: onRevoke)
                }
            } else {
                Button("Attest Ownership…", action: onAttest)
            }
        }
    }
}

private struct DomainVerificationRow: View {
    let record: DomainRecord
    let onRestart: () -> Void
    let onCheck: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label(record.domain, systemImage: "globe").font(.body.weight(.medium))
                Spacer()
                VerificationBadge(status: record.verificationStatus)
                switch record.verificationStatus {
                case .ownershipPending: Button("Check DNS", action: onCheck)
                case .ownershipVerified: EmptyView()
                default: Button("Verify…", action: onRestart)
                }
            }
            if record.verificationStatus == .ownershipPending, let name = record.challengeRecordName, let value = record.challengeValue {
                VStack(alignment: .leading, spacing: 4) {
                    CopyableValue(label: "TXT name", value: name)
                    CopyableValue(label: "TXT value", value: value)
                }
                .padding(10)
                .background(Theme.elevated, in: .rect(cornerRadius: 8))
            }
        }
    }
}

private struct CopyableValue: View {
    let label: String
    let value: String

    var body: some View {
        HStack {
            Text(label).font(.caption).foregroundStyle(.spectreSecondary).frame(width: 70, alignment: .leading)
            Text(value).font(.caption.monospaced()).textSelection(.enabled)
            Spacer()
            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(value, forType: .string)
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .accessibilityLabel(Text("Copy \(label)"))
        }
    }
}

private struct AttestationSheet: View {
    @Environment(\.dismiss) private var dismiss
    let initialEmail: String
    let onSubmit: (String, String) -> Void
    @State private var email = ""
    @State private var statement = ""
    @State private var confirmed = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Attest mailbox ownership").font(.title2.weight(.semibold))
            Text("Attest only for addresses you own or for which you hold written authorization from the owner. Your statement is stored with the record and in the audit log.")
                .font(.callout)
                .foregroundStyle(.spectreSecondary)
            TextField("Email address", text: $email)
            TextField("Statement", text: $statement, prompt: Text("e.g. This is my personal mailbox"), axis: .vertical)
                .lineLimit(2...4)
            Toggle("I own this mailbox or am authorized in writing by its owner", isOn: $confirmed)
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                Button("Attest") {
                    onSubmit(email, statement)
                    dismiss()
                }
                .buttonStyle(.borderedProminent)
                .disabled(!confirmed || email.isEmpty || statement.trimmingCharacters(in: .whitespaces).count < 10)
            }
        }
        .padding(24)
        .frame(width: 480)
        .onAppear { email = initialEmail }
    }
}

// MARK: - Exposure report

private struct ExposureReportView: View {
    @Environment(AppModel.self) private var model
    @Binding var email: String?
    @State private var verified: [EmailRecord] = []
    @State private var report: BreachExposureReport?
    @State private var isLoading = false
    @State private var errorMessage: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Theme.spacing) {
                HStack {
                    Picker("Verified address", selection: $email) {
                        Text("Choose a verified address").tag(String?.none)
                        ForEach(verified) { Text($0.email).tag(String?.some($0.email)) }
                    }
                    .frame(maxWidth: 380)
                    Spacer()
                    Button {
                        lookup()
                    } label: {
                        if isLoading { ProgressView().controlSize(.small) } else { Label("Check Known Breaches", systemImage: "magnifyingglass") }
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(Theme.accent)
                    .disabled(email == nil || isLoading)
                }
                if let errorMessage {
                    Label(errorMessage, systemImage: "exclamationmark.triangle.fill").foregroundStyle(Theme.danger)
                }
                if let report {
                    BreachReportContent(report: report)
                } else if verified.isEmpty {
                    ContentUnavailableView("No verified addresses", systemImage: "envelope.badge.shield.half.filled", description: Text("Verify ownership of an address first."))
                }
            }
            .padding(20)
        }
        .task {
            await loadVerified()
            await loadStored()
        }
        .onChange(of: email) { _, _ in Task { await loadStored() } }
    }

    private func loadVerified() async {
        guard let engine = model.engine else { return }
        verified = ((try? await engine.verifications().emails) ?? []).filter { $0.verificationStatus == .ownershipVerified }
        if email == nil { email = verified.first?.email }
    }

    private func loadStored() async {
        guard let engine = model.engine, let email else { report = nil; return }
        report = try? await engine.storedExposures(email: email)
    }

    private func lookup() {
        guard let engine = model.engine, let email else { return }
        isLoading = true
        errorMessage = nil
        Task {
            do {
                report = try await engine.lookupBreaches(email: email, investigationID: nil)
            } catch {
                errorMessage = error.localizedDescription
            }
            isLoading = false
        }
    }
}

struct BreachReportContent: View {
    @Environment(AppModel.self) private var model
    let report: BreachExposureReport

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.spacing) {
            Card {
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        Text(report.email).font(.title2.weight(.semibold))
                        Spacer()
                        RiskBadge(level: report.risk.level)
                    }
                    Text("\(report.breaches.count) known breach(es) · checked \(report.checkedAt.formatted(.relative(presentation: .named)))")
                        .foregroundStyle(.spectreSecondary)
                    if let method = report.verificationMethod {
                        TagChip(text: "Verified by \(method.label.lowercased())", tint: Theme.success, symbol: "checkmark.shield")
                    }
                    Text(report.sourceAttribution).font(.caption2).foregroundStyle(.spectreSecondary)
                }
            }
            if !report.breaches.isEmpty {
                Card {
                    VStack(alignment: .leading, spacing: 10) {
                        SectionHeader(title: "Exposure timeline", symbol: "calendar")
                        Chart(report.breaches.filter { $0.breachDay != nil }) { breach in
                            PointMark(x: .value("Date", breach.breachDay ?? .now), y: .value("Accounts", breach.pwnCount))
                                .foregroundStyle(breach.passwordDataExposed ? Theme.danger : Theme.warning)
                                .symbolSize(120)
                                .annotation(position: .top) { Text(breach.title).font(.caption2) }
                        }
                        .chartYScale(type: .log)
                        .frame(height: 200)
                    }
                }
            }
            if !report.risk.indicators.isEmpty {
                Card {
                    VStack(alignment: .leading, spacing: 8) {
                        SectionHeader(title: "Risk indicators", symbol: "exclamationmark.triangle", count: report.risk.indicators.count)
                        ForEach(report.risk.indicators, id: \.self) { indicator in
                            VStack(alignment: .leading, spacing: 2) {
                                HStack {
                                    Text(indicator.title).font(.callout.weight(.medium))
                                    Spacer()
                                    RiskBadge(level: indicator.severity)
                                }
                                Text(indicator.detail).font(.caption).foregroundStyle(.spectreSecondary)
                            }
                        }
                    }
                }
            }
            Card {
                VStack(alignment: .leading, spacing: 8) {
                    SectionHeader(title: "Remediation", symbol: "checkmark.shield")
                    ForEach(report.risk.recommendations, id: \.self) { Label($0, systemImage: "checkmark.circle").font(.callout) }
                }
            }
            ForEach(report.breaches) { breach in
                Card {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text(breach.title).font(.headline)
                            Spacer()
                            Button("Inspect") { model.inspect(.breach(breach)) }.buttonStyle(.link)
                        }
                        BreachIncidentDetail(incident: breach)
                    }
                }
            }
        }
    }
}

// MARK: - Catalog

private struct BreachCatalogView: View {
    @Environment(AppModel.self) private var model
    @State private var query = ""
    @State private var result = CatalogSearchResult(total: 0, breaches: [])
    @State private var isRefreshing = false
    @State private var errorMessage: String?
    @State private var selection: BreachIncident.ID?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("\(result.total) breaches cached locally · public metadata from Have I Been Pwned (CC BY 4.0)")
                    .font(.caption)
                    .foregroundStyle(.spectreSecondary)
                Spacer()
                if let errorMessage { Text(errorMessage).font(.caption).foregroundStyle(Theme.danger) }
                Button {
                    refresh()
                } label: {
                    if isRefreshing { ProgressView().controlSize(.small) } else { Label("Refresh Catalog", systemImage: "arrow.clockwise") }
                }
                .disabled(isRefreshing)
            }
            .padding(12)
            Table(result.breaches, selection: $selection) {
                TableColumn("Breach") { breach in Text(breach.title) }
                TableColumn("Domain") { breach in Text(breach.domain ?? "None").foregroundStyle(.spectreSecondary) }
                TableColumn("Date") { breach in Text(breach.breachDate ?? "Unknown").monospacedDigit() }.width(90)
                TableColumn("Accounts") { breach in Text(breach.pwnCount, format: .number).monospacedDigit() }.width(110)
                TableColumn("Passwords") { breach in
                    Image(systemName: breach.passwordDataExposed ? "key.fill" : "minus")
                        .foregroundStyle(breach.passwordDataExposed ? Theme.danger : Theme.secondaryText)
                        .accessibilityLabel(breach.passwordDataExposed ? Text("Password data exposed") : Text("No password data"))
                }
                .width(70)
            }
        }
        .searchable(text: $query, prompt: "Search breaches or domains")
        .task(id: query) {
            try? await Task.sleep(for: .milliseconds(200))
            await search()
        }
        .onChange(of: selection) { _, identifier in
            if let breach = result.breaches.first(where: { $0.id == identifier }) { model.inspect(.breach(breach)) }
        }
    }

    private func search() async {
        guard let engine = model.engine else { return }
        result = (try? await engine.searchBreachCatalog(query: query.isEmpty ? nil : query, limit: 500)) ?? result
    }

    private func refresh() {
        guard let engine = model.engine else { return }
        isRefreshing = true
        errorMessage = nil
        Task {
            do {
                _ = try await engine.refreshBreachCatalog()
                await search()
            } catch {
                errorMessage = error.localizedDescription
            }
            isRefreshing = false
        }
    }
}

#Preview("Breach Intelligence") {
    NavigationStack { BreachIntelligenceView() }
        .environment(AppModel(engine: PreviewEngine()))
        .frame(width: 900, height: 700)
}

#Preview("Report") {
    ScrollView { BreachReportContent(report: PreviewData.report).padding() }
        .environment(AppModel(engine: PreviewEngine()))
        .frame(width: 760, height: 800)
}

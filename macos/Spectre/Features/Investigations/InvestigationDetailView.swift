import SwiftUI

struct InvestigationDetailView: View {
    @Environment(AppModel.self) private var model
    let session: InvestigationViewModel
    @State private var tab: DetailTab = .findings

    enum DetailTab: String, CaseIterable, Identifiable {
        case findings = "Findings"
        case identities = "Identities"
        case breaches = "Breaches"
        case risk = "Risk"
        case followUps = "Follow-ups"
        case diagnostics = "Run Details"
        var id: String { rawValue }
    }

    var body: some View {
        VStack(spacing: 0) {
            InvestigationHeader(session: session)
                .padding(20)
            DetailTabPicker(tab: $tab)
                .padding(.horizontal, 20)
                .padding(.bottom, 12)
            Divider()
            switch tab {
            case .findings: FindingsList(sections: session.sections, isRunning: session.isRunning)
            case .identities: RelationshipList(session: session)
            case .breaches: BreachExposureTab(session: session)
            case .risk: RiskIndicatorsTab(findings: session.findings)
            case .followUps: FollowUpsTab(investigationID: session.id, target: session.investigation?.target, isRunning: session.isRunning)
            case .diagnostics: RunDetailsTab(investigation: session.investigation, providerStates: session.providerStates)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle(session.investigation?.target.value ?? "Investigation")
        .navigationSubtitle(session.investigation?.targetType.label ?? "")
        .task { await session.load() }
        .alert("Action failed", isPresented: Binding(get: { session.actionError != nil }, set: { if !$0 { session.dismissError() } })) {
            Button("OK") { session.dismissError() }
        } message: {
            Text(session.actionError ?? "")
        }
    }
}

private struct DetailTabPicker: View {
    @Binding var tab: InvestigationDetailView.DetailTab

    var body: some View {
        // Six segments need about 540 points; below that a menu keeps every tab reachable.
        ViewThatFits(in: .horizontal) {
            Picker("Section", selection: $tab) {
                ForEach(InvestigationDetailView.DetailTab.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .fixedSize()
            Picker("Section", selection: $tab) {
                ForEach(InvestigationDetailView.DetailTab.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.menu)
            .fixedSize()
        }
        .labelsHidden()
        .frame(maxWidth: .infinity)
    }
}

private struct InvestigationHeader: View {
    let session: InvestigationViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .center, spacing: 12) {
                Image(systemName: session.investigation?.targetType.symbol ?? "magnifyingglass")
                    .font(.title)
                    .foregroundStyle(Theme.accent)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(session.investigation?.target.value ?? "…").font(.title2.weight(.semibold)).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                    Text(session.investigation?.purpose ?? "").font(.callout).foregroundStyle(.spectreSecondary).lineLimit(2)
                }
                .layoutPriority(1)
                Spacer(minLength: 8)
                StatusBadge(status: session.status)
                if session.isRunning {
                    Button(role: .destructive) {
                        Task { await session.cancel() }
                    } label: {
                        Label("Cancel", systemImage: "stop.fill")
                    }
                }
            }
            if session.isRunning {
                ProgressView(value: session.progress) {
                    Text("\(session.findings.count) findings so far")
                        .font(.caption)
                        .foregroundStyle(.spectreSecondary)
                }
                .tint(Theme.accent)
            }
            ProviderStrip(states: session.providerStates)
        }
    }
}

private struct ProviderStrip: View {
    let states: [String: ProviderRunState]

    var body: some View {
        FlowLayout(spacing: 6) {
            ForEach(states.keys.sorted(), id: \.self) { provider in
                ProviderChip(provider: provider, state: states[provider] ?? .pending)
            }
        }
    }
}

private struct ProviderChip: View {
    let provider: String
    let state: ProviderRunState

    var body: some View {
        switch state {
        case .pending: TagChip(text: provider, symbol: "clock")
        case .running: TagChip(text: provider, tint: Theme.secondaryAccent, symbol: "arrow.triangle.2.circlepath")
        case .completed(let findings, let latency):
            TagChip(text: "\(provider) · \(findings) · \(latency) ms", tint: findings > 0 ? Theme.success : Theme.secondaryText, symbol: "checkmark")
        case .failed(_, let message):
            TagChip(text: provider, tint: Theme.danger, symbol: "exclamationmark.triangle").help(message)
        case .cancelled: TagChip(text: provider, symbol: "stop")
        }
    }
}

private struct FindingsList: View {
    @Environment(AppModel.self) private var model
    let sections: [FindingSection]
    let isRunning: Bool
    @State private var selection: Finding.ID?

    var body: some View {
        if sections.isEmpty {
            ContentUnavailableView {
                Label(isRunning ? "Searching public sources…" : "No findings", systemImage: isRunning ? "antenna.radiowaves.left.and.right" : "tray")
            } description: {
                Text(isRunning ? "Findings appear here as each provider responds." : "No provider reported public information for this target.")
            }
        } else {
            List(selection: $selection) {
                ForEach(sections) { section in
                    Section {
                        ForEach(section.findings) { finding in
                            FindingRow(finding: finding).tag(finding.id)
                        }
                    } header: {
                        Label(section.kind.label, systemImage: section.kind.symbol)
                    }
                }
            }
            .listStyle(.inset)
            .onChange(of: selection) { _, identifier in
                guard let identifier else { return }
                if let finding = sections.lazy.flatMap(\.findings).first(where: { $0.id == identifier }) {
                    model.inspect(.finding(finding))
                }
            }
        }
    }
}

struct RelationshipList: View {
    @Environment(AppModel.self) private var model
    let session: InvestigationViewModel

    var body: some View {
        let nodes = Dictionary(uniqueKeysWithValues: session.graph.nodes.map { ($0.id, $0) })
        if session.graph.edges.isEmpty {
            ContentUnavailableView("No relationships yet", systemImage: "point.3.connected.trianglepath.dotted", description: Text("Relationships are computed when the investigation finishes."))
        } else {
            List {
                Section {
                    ForEach(session.graph.edges) { edge in
                        RelationshipRow(
                            sourceLabel: nodes[edge.sourceIdentity]?.label ?? "?",
                            targetLabel: nodes[edge.targetIdentity]?.label ?? "?",
                            relationship: edge.relationship,
                            category: edge.category,
                            score: edge.confidence,
                            decision: edge.investigatorDecision,
                            isEditable: edge.relationship != .exposedInBreach && !session.isRunning
                        ) { decision in
                            Task { await session.decide(edge.id, decision: decision) }
                        } onSelect: {
                            model.inspect(.relationship(edge, source: nodes[edge.sourceIdentity], target: nodes[edge.targetIdentity]))
                        }
                    }
                } header: {
                    HStack {
                        Text("\(session.graph.edges.count) relationships")
                        Spacer()
                        Button("Open Graph") { model.selection = .identities }.buttonStyle(.link)
                    }
                } footer: {
                    Text("Confirm or reject associations after reviewing their evidence. Decisions are recorded in the audit log and survive re-correlation.")
                }
            }
            .listStyle(.inset)
        }
    }
}

struct RelationshipRow: View {
    let sourceLabel: String
    let targetLabel: String
    let relationship: RelationshipKind
    let category: ConfidenceCategory
    let score: Double
    let decision: InvestigatorDecision?
    let isEditable: Bool
    let onDecide: (InvestigatorDecision?) -> Void
    let onSelect: () -> Void

    var body: some View {
        // The badge sits under the labels so long identity names have the full row to wrap in.
        HStack(alignment: .top, spacing: 8) {
            VStack(alignment: .leading, spacing: 6) {
                RelationshipSummary(sourceLabel: sourceLabel, targetLabel: targetLabel, relationship: relationship, score: score)
                ConfidenceBadge(category: category)
            }
            Spacer(minLength: 0)
            if isEditable { DecisionControls(decision: decision, onDecide: onDecide) }
        }
        .contentShape(.rect)
        .onTapGesture(perform: onSelect)
    }
}

private struct RelationshipSummary: View {
    let sourceLabel: String
    let targetLabel: String
    let relationship: RelationshipKind
    let score: Double

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text("\(sourceLabel) \(Image(systemName: "arrow.right")) \(Text(targetLabel).fontWeight(.medium))")
                .lineLimit(2)
                .accessibilityLabel(Text("\(sourceLabel) to \(targetLabel)"))
            Text("\(relationship.label) · score \(score, format: .number.precision(.fractionLength(2)))")
                .font(.caption)
                .foregroundStyle(.spectreSecondary)
        }
    }
}

private struct DecisionControls: View {
    let decision: InvestigatorDecision?
    let onDecide: (InvestigatorDecision?) -> Void

    var body: some View {
        ControlGroup {
            Button { onDecide(decision == .confirmed ? nil : .confirmed) } label: {
                Image(systemName: decision == .confirmed ? "checkmark.circle.fill" : "checkmark.circle")
            }
            .help("Confirm association")
            .accessibilityLabel(Text("Confirm association"))
            Button { onDecide(decision == .rejected ? nil : .rejected) } label: {
                Image(systemName: decision == .rejected ? "xmark.circle.fill" : "xmark.circle")
            }
            .help("Reject association")
            .accessibilityLabel(Text("Reject association"))
        }
        .controlGroupStyle(.navigation)
        .fixedSize()
    }
}

private struct BreachExposureTab: View {
    @Environment(AppModel.self) private var model
    let session: InvestigationViewModel
    @State private var records: [EmailRecord] = []
    @State private var isChecking: String?
    @State private var errorMessage: String?

    private var emails: [String] {
        var addresses: [String] = []
        if let target = session.investigation?.target, target.type == .email { addresses.append(target.value) }
        for finding in session.findings {
            if case .emailAssociation(let association) = finding.data, !addresses.contains(association.email) {
                addresses.append(association.email)
            }
        }
        return addresses
    }

    private var breachFindings: [Finding] {
        session.findings.filter { $0.kind == .breachIncident }
    }

    var body: some View {
        List {
            Section {
                if emails.isEmpty {
                    Text("No email addresses in this investigation.").foregroundStyle(.spectreSecondary)
                }
                ForEach(emails, id: \.self) { email in
                    let record = records.first { $0.email == email }
                    HStack {
                        Label(email, systemImage: "envelope")
                        Spacer()
                        VerificationBadge(status: record?.verificationStatus ?? .unverified)
                        if record?.verificationStatus == .ownershipVerified {
                            Button("Check Breaches") { check(email) }
                                .disabled(isChecking != nil || session.isRunning)
                        } else {
                            Button("Verify Ownership…") { model.selection = .breaches }
                        }
                        if isChecking == email { ProgressView().controlSize(.small) }
                    }
                }
            } header: {
                Text("Addresses")
            } footer: {
                Text("Account-specific breach data is only requested for ownership-verified addresses (DNS challenge or recorded attestation).")
            }
            if let errorMessage {
                Label(errorMessage, systemImage: "exclamationmark.triangle.fill").foregroundStyle(Theme.danger)
            }
            if !breachFindings.isEmpty {
                Section("Known breaches") {
                    ForEach(breachFindings) { finding in
                        FindingRow(finding: finding)
                            .onTapGesture { model.inspect(.finding(finding)) }
                    }
                }
            }
        }
        .listStyle(.inset)
        .task(id: emails) { await loadRecords() }
    }

    private func loadRecords() async {
        guard let engine = model.engine else { return }
        records = (try? await engine.verifications().emails) ?? []
    }

    private func check(_ email: String) {
        guard let engine = model.engine else { return }
        isChecking = email
        errorMessage = nil
        Task {
            do {
                _ = try await engine.lookupBreaches(email: email, investigationID: session.id)
                await session.reload()
            } catch {
                errorMessage = error.localizedDescription
            }
            isChecking = nil
        }
    }
}

/// Aggregated risk signals across the investigation's findings.
private struct RiskIndicatorsTab: View {
    let findings: [Finding]

    private var indicators: [(symbol: String, tint: Color, text: String)] {
        var items: [(String, Color, String)] = []
        for finding in findings {
            switch finding.data {
            case .dnsRecords(let dns):
                items += dns.observations.map { ("network.badge.shield.half.filled", Theme.warning, $0) }
            case .emailIntelligence(let mail):
                if mail.spf == nil { items.append(("envelope.badge.shield.half.filled", Theme.warning, "\(mail.domain) publishes no SPF record")) }
                if mail.dmarc == nil { items.append(("envelope.badge.shield.half.filled", Theme.warning, "\(mail.domain) publishes no DMARC policy")) }
            case .breachIncident(let breach):
                let label = breach.exposedAccount.map { "\($0) appears in \(breach.incident.title)" } ?? "\(breach.incident.title) breach affected this service"
                items.append(("exclamationmark.shield.fill", breach.incident.passwordDataExposed ? Theme.danger : Theme.warning, label))
            case .emailAssociation(let association):
                items.append(("at.badge.plus", Theme.secondaryAccent, "\(association.email) is publicly associated (\(association.sourceDescription))"))
            case .profile(let profile) where profile.publicEmail != nil:
                items.append(("person.crop.circle.badge.exclamationmark", Theme.secondaryAccent, "\(profile.platform) profile publishes an email address"))
            case .webPresence(let web):
                if web.securityTxt == nil {
                    items.append(("doc.badge.ellipsis", Theme.secondaryText, "No security.txt published at \(web.url)"))
                }
                for check in web.headerChecks ?? [] {
                    if let note = check.note { items.append(("lock.trianglebadge.exclamationmark", Theme.warning, "\(check.header): \(note)")) }
                }
            default:
                break
            }
        }
        return items
    }

    var body: some View {
        let items = indicators
        if items.isEmpty {
            ContentUnavailableView("No risk indicators", systemImage: "checkmark.shield", description: Text("Nothing in the current findings needs attention."))
        } else {
            List(items.indices, id: \.self) { index in
                Label(items[index].text, systemImage: items[index].symbol).foregroundStyle(items[index].tint)
            }
            .listStyle(.inset)
        }
    }
}

private struct RunDetailsTab: View {
    let investigation: Investigation?
    let providerStates: [String: ProviderRunState]

    var body: some View {
        Form {
            if let metrics = investigation?.metrics {
                Section("Performance") {
                    KeyValueRow(label: "Startup latency", value: "\(metrics.startupLatencyMs) ms")
                    KeyValueRow(label: "Time to first finding", value: metrics.timeToFirstFindingMs.map { "\($0) ms" } ?? "None")
                    KeyValueRow(label: "Total duration", value: "\(metrics.totalDurationMs) ms")
                    KeyValueRow(label: "HTTP requests", value: "\(metrics.httpRequests)")
                    KeyValueRow(label: "Cache hit rate", value: metrics.cacheHitRate.map { $0.formatted(.percent.precision(.fractionLength(0))) } ?? "None")
                }
                Section("Provider latency") {
                    ForEach(metrics.providerLatencies.sorted { $0.latencyMs > $1.latencyMs }, id: \.providerId) { latency in
                        LabeledContent(latency.providerId) {
                            Text("\(latency.latencyMs) ms · \(latency.outcome.rawValue.humanizedKey) · \(latency.findings)")
                                .monospacedDigit()
                        }
                    }
                }
            }
            Section("Errors") {
                if investigation?.errors.isEmpty ?? true {
                    Text("No provider errors").foregroundStyle(.spectreSecondary)
                }
                ForEach(investigation?.errors ?? [], id: \.self) { failure in
                    VStack(alignment: .leading, spacing: 2) {
                        Text("\(failure.providerId) · \(failure.code.rawValue.humanizedKey)").font(.callout.weight(.medium))
                        Text(failure.message).font(.caption).foregroundStyle(.spectreSecondary)
                    }
                }
            }
            if let investigation {
                Section("Record") {
                    KeyValueRow(label: "Identifier", value: investigation.id.uuidString.lowercased())
                    KeyValueRow(label: "Created", value: investigation.createdAt.formatted(date: .abbreviated, time: .standard))
                    if let completed = investigation.completedAt {
                        KeyValueRow(label: "Completed", value: completed.formatted(date: .abbreviated, time: .standard))
                    }
                    KeyValueRow(label: "Authorization", value: investigation.purpose)
                }
            }
        }
        .formStyle(.grouped)
    }
}

#Preview {
    let model = AppModel(engine: PreviewEngine())
    NavigationStack {
        InvestigationDetailView(session: InvestigationViewModel(id: PreviewData.investigationID, engine: PreviewEngine(), initial: PreviewData.investigation))
    }
    .environment(model)
    .frame(width: 900, height: 700)
}

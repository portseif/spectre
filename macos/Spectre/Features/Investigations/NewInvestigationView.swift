import SwiftUI

struct NewInvestigationView: View {
    @Environment(AppModel.self) private var model
    @AppStorage("defaultTargetType") private var defaultTargetType: TargetType = .username
    @AppStorage("lastAuthorizationBasis") private var lastBasis = ""
    @State private var targetType: TargetType = .username
    @State private var value = ""
    @State private var region = ""
    @State private var purpose = ""
    @State private var attested = false
    @State private var validation: TargetValidation?
    @State private var providers: [ProviderStatus] = []
    @State private var selectedProviders: Set<String> = []
    @State private var isStarting = false
    @State private var errorMessage: String?

    private var applicableProviders: [ProviderStatus] {
        providers.filter { $0.supportedTargets.contains(targetType) }
    }

    private var canStart: Bool {
        validation?.valid == true && purpose.trimmingCharacters(in: .whitespacesAndNewlines).count >= 10 && attested
            && !selectedProviders.isEmpty && !isStarting
    }

    var body: some View {
        Form {
            Section {
                Picker("Search type", selection: $targetType) {
                    ForEach(TargetType.allCases) { type in
                        Label(type.label, systemImage: type.symbol).tag(type)
                    }
                }
                .pickerStyle(.segmented)
                TextField(targetType.label, text: $value, prompt: Text(targetType.placeholder))
                    .textFieldStyle(.roundedBorder)
                    .font(.title3)
                    .onSubmit(start)
                if targetType == .phone {
                    TextField("Default region", text: $region, prompt: Text("US (only for numbers without +country code)"))
                }
                ValidationLine(validation: validation, isEmpty: value.isEmpty)
            } header: {
                Text("Target")
            }

            Section {
                HStack(alignment: .top, spacing: 8) {
                    TextField("Authorization basis and scope", text: $purpose, prompt: Text("e.g. engagement #1234 for Acme Corp"), axis: .vertical)
                        .lineLimit(1...3)
                    Button("Self-assessment") {
                        purpose = Self.selfAssessmentBasis
                        attested = true
                    }
                    .help("Fill in a self-assessment basis and confirm authorization")
                }
                Toggle("I am authorized to investigate this target for the purpose above", isOn: $attested)
            } header: {
                Text("Authorization")
            } footer: {
                Text("The purpose is recorded with the investigation and in the audit log. Discovery uses public sources only and never escalates to private account access.")
            }

            Section {
                if applicableProviders.isEmpty {
                    Text("Loading providers…").foregroundStyle(.spectreSecondary)
                }
                ForEach(applicableProviders) { provider in
                    Toggle(isOn: binding(for: provider.id)) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(provider.name)
                            Text(provider.description).font(.caption).foregroundStyle(.spectreSecondary)
                        }
                    }
                }
            } header: {
                HStack {
                    Text("Providers")
                    Spacer()
                    Button("All") { selectedProviders = Set(applicableProviders.map(\.id)) }.buttonStyle(.link)
                    Button("None") { selectedProviders = [] }.buttonStyle(.link)
                }
            }

            Section {
                HStack {
                    if let errorMessage {
                        Label(errorMessage, systemImage: "exclamationmark.triangle.fill").foregroundStyle(Theme.danger)
                    }
                    Spacer()
                    Button(action: start) {
                        if isStarting { ProgressView().controlSize(.small) } else { Label("Start Investigation", systemImage: "play.fill") }
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(Theme.accent)
                    .controlSize(.large)
                    .disabled(!canStart)
                    .keyboardShortcut(.return, modifiers: .command)
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("New Investigation")
        .task {
            targetType = defaultTargetType
            applyDraft()
            if purpose.isEmpty { purpose = lastBasis }
            await loadProviders()
        }
        .onChange(of: model.draftTarget) { _, _ in applyDraft() }
        .task(id: ValidationKey(type: targetType, value: value, region: region)) { await validate() }
        .onChange(of: targetType) { _, _ in resetProviderSelection() }
    }

    private static let selfAssessmentBasis = "Self-assessment of my own accounts"

    private func applyDraft() {
        guard let draft = model.draftTarget else { return }
        targetType = draft.type
        value = draft.value
        purpose = ""
        attested = false
        model.draftTarget = nil
    }

    private func binding(for providerID: String) -> Binding<Bool> {
        Binding {
            selectedProviders.contains(providerID)
        } set: { isOn in
            if isOn { selectedProviders.insert(providerID) } else { selectedProviders.remove(providerID) }
        }
    }

    private func loadProviders() async {
        guard let engine = model.engine else { return }
        do {
            providers = try await engine.providers().providers
            resetProviderSelection()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func resetProviderSelection() {
        selectedProviders = Set(applicableProviders.filter(\.enabled).map(\.id))
    }

    private func validate() async {
        guard let engine = model.engine, !value.isEmpty else {
            validation = nil
            return
        }
        // Debounce keystrokes; the task is cancelled when the input changes.
        try? await Task.sleep(for: .milliseconds(200))
        guard !Task.isCancelled else { return }
        validation = try? await engine.validateTarget(targetType, value: value, region: region.isEmpty ? nil : region)
    }

    private func start() {
        guard canStart else { return }
        isStarting = true
        errorMessage = nil
        let request = StartInvestigationRequest(
            targetType: targetType,
            value: value,
            purpose: purpose,
            providerIds: Array(selectedProviders).sorted(),
            defaultRegion: region.isEmpty ? nil : region
        )
        Task {
            do {
                try await model.start(request)
                lastBasis = purpose.trimmingCharacters(in: .whitespacesAndNewlines)
                value = ""
                validation = nil
            } catch {
                errorMessage = error.localizedDescription
            }
            isStarting = false
        }
    }
}

private struct ValidationKey: Equatable {
    let type: TargetType
    let value: String
    let region: String
}

private struct ValidationLine: View {
    let validation: TargetValidation?
    let isEmpty: Bool

    var body: some View {
        if let validation, !isEmpty {
            if validation.valid {
                VStack(alignment: .leading, spacing: 2) {
                    Label("Normalized: \(validation.normalized ?? "")", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(Theme.success)
                    if let phone = validation.phone {
                        Text("\(phone.internationalFormat) · \(phone.regionCode ?? "non-geographic") · \(phone.numberType.humanizedKey)")
                            .font(.caption)
                            .foregroundStyle(.spectreSecondary)
                    }
                }
                .font(.callout)
            } else {
                Label(validation.error ?? "Invalid input", systemImage: "xmark.circle.fill")
                    .foregroundStyle(Theme.danger)
                    .font(.callout)
            }
        }
    }
}

#Preview {
    NavigationStack {
        NewInvestigationView()
    }
    .environment(AppModel(engine: PreviewEngine()))
    .frame(width: 760, height: 720)
}

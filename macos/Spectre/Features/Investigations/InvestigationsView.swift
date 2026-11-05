import SwiftUI

/// Stored investigations with drill-down into a live detail view.
struct InvestigationsView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        NavigationStack(path: $model.investigationPath) {
            InvestigationTable()
                .navigationDestination(for: UUID.self) { identifier in
                    if let session = model.session(for: identifier) {
                        InvestigationDetailView(session: session)
                    }
                }
        }
    }
}

private struct InvestigationTable: View {
    @Environment(AppModel.self) private var model
    @State private var selection: Investigation.ID?
    @State private var pendingDeletion: Investigation?
    @State private var errorMessage: String?

    var body: some View {
        @Bindable var model = model
        Group {
            if model.investigations.isEmpty {
                ContentUnavailableView {
                    Label("No investigations", systemImage: "magnifyingglass")
                } description: {
                    Text(model.searchText.isEmpty ? "Start a new investigation to discover public information." : "No investigations match “\(model.searchText)”.")
                } actions: {
                    Button("New Investigation") { model.selection = .newInvestigation }
                }
            } else {
                Table(model.investigations, selection: $selection) {
                    TableColumn("Target") { investigation in
                        Label(investigation.target.value, systemImage: investigation.targetType.symbol)
                    }
                    TableColumn("Status") { investigation in
                        StatusBadge(status: investigation.status)
                    }
                    .width(min: 120, ideal: 150)
                    TableColumn("Findings") { investigation in
                        Text(investigation.findingsCount, format: .number).monospacedDigit()
                    }
                    .width(70)
                    TableColumn("Errors") { investigation in
                        Text(investigation.errors.count, format: .number).monospacedDigit()
                            .foregroundStyle(investigation.errors.isEmpty ? Theme.secondaryText : Theme.warning)
                    }
                    .width(60)
                    TableColumn("Started") { investigation in
                        Text(investigation.createdAt, format: .dateTime.month().day().hour().minute())
                    }
                    .width(min: 120, ideal: 140)
                    TableColumn("Purpose") { investigation in
                        Text(investigation.purpose).lineLimit(1).foregroundStyle(.spectreSecondary)
                    }
                }
                .contextMenu(forSelectionType: Investigation.ID.self) { identifiers in
                    if let identifier = identifiers.first, let investigation = model.investigations.first(where: { $0.id == identifier }) {
                        Button("Open") { model.open(identifier) }
                        Button("Delete…", role: .destructive) { pendingDeletion = investigation }
                    }
                } primaryAction: { identifiers in
                    if let identifier = identifiers.first { model.open(identifier) }
                }
            }
        }
        .navigationTitle("Investigations")
        .searchable(text: $model.searchText, prompt: "Search targets and purposes")
        .onSubmit(of: .search) { Task { await model.refreshInvestigations() } }
        .onChange(of: model.searchText) { _, newValue in
            if newValue.isEmpty { Task { await model.refreshInvestigations() } }
        }
        .toolbar {
            ToolbarItemGroup {
                Button {
                    Task { await model.refreshInvestigations() }
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                Button {
                    if let selection { model.open(selection) }
                } label: {
                    Label("Open", systemImage: "arrow.right.circle")
                }
                .disabled(selection == nil)
            }
        }
        .task { await model.refreshInvestigations() }
        .confirmationDialog("Delete this investigation?", isPresented: Binding(get: { pendingDeletion != nil }, set: { if !$0 { pendingDeletion = nil } }), presenting: pendingDeletion) { investigation in
            Button("Delete \(investigation.target.value)", role: .destructive) {
                Task {
                    do { try await model.delete(investigation.id) } catch { errorMessage = error.localizedDescription }
                }
            }
        } message: { _ in
            Text("Findings, identities, and relationships are permanently removed (SQLite secure delete). The audit log keeps a record that the investigation existed.")
        }
        .alert("Could not delete", isPresented: Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "")
        }
    }
}

#Preview {
    InvestigationsView()
        .environment(AppModel(engine: PreviewEngine()))
        .frame(width: 900, height: 500)
}

import SwiftUI

struct RootView: View {
    @AppStorage("appearance") private var appearance: AppearancePreference = .system

    var body: some View {
        PhaseView()
            .preferredColorScheme(appearance.colorScheme)
    }
}

private struct PhaseView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        switch model.phase {
        case .starting:
            ProgressView("Starting engine…")
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        case .failed(let message):
            ContentUnavailableView {
                Label("The engine could not start", systemImage: "exclamationmark.triangle")
            } description: {
                Text(message)
            }
        case .ready:
            MainSplitView()
        }
    }
}

private struct MainSplitView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        NavigationSplitView {
            SidebarView(selection: $model.selection)
                .navigationSplitViewColumnWidth(min: 200, ideal: 220, max: 280)
        } detail: {
            DetailColumn(selection: model.selection ?? .dashboard)
                // Bound the ideal width: greedy content (flow layouts, canvases)
                // would otherwise claim its ideal and collapse the sidebar or inspector.
                .frame(minWidth: 560, idealWidth: 720, maxWidth: .infinity, maxHeight: .infinity)
                .background(Theme.background)
                .inspector(isPresented: $model.isInspectorPresented) {
                    InspectorView(item: model.inspector)
                        .inspectorColumnWidth(min: 240, ideal: 300, max: 420)
                }
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    model.isInspectorPresented.toggle()
                } label: {
                    Label("Inspector", systemImage: "sidebar.trailing")
                }
                .help("Show or hide the inspector")
            }
        }
    }
}

private struct SidebarView: View {
    @Binding var selection: SidebarItem?

    var body: some View {
        List(selection: $selection) {
            Section("Intelligence") {
                ForEach([SidebarItem.dashboard, .newInvestigation, .investigations, .identities]) { item in
                    Label(item.title, systemImage: item.symbol).tag(item)
                }
            }
            Section("Security") {
                ForEach([SidebarItem.breaches, .securityAudits, .reports]) { item in
                    Label(item.title, systemImage: item.symbol).tag(item)
                }
            }
            Section {
                Label(SidebarItem.settings.title, systemImage: SidebarItem.settings.symbol).tag(SidebarItem.settings)
            }
        }
        .listStyle(.sidebar)
        .navigationTitle("Spectre")
    }
}

private struct DetailColumn: View {
    let selection: SidebarItem

    var body: some View {
        switch selection {
        case .dashboard: DashboardView()
        case .newInvestigation: NewInvestigationView()
        case .investigations: InvestigationsView()
        case .identities: IdentitiesView()
        case .breaches: BreachIntelligenceView()
        case .securityAudits: SecurityAuditView()
        case .reports: ReportsView()
        case .settings: SettingsView()
        }
    }
}

#Preview {
    RootView()
        .environment(AppModel(engine: PreviewEngine()))
        .frame(width: 1200, height: 760)
}

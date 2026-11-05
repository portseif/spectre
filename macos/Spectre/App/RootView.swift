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
    @State private var columnVisibility: NavigationSplitViewVisibility = .all
    @State private var windowWidth: CGFloat = 0
    @State private var sidebarHiddenForInspector = false

    /// Below this width the sidebar, detail and inspector do not all fit.
    private static let widthForAllColumns: CGFloat = 1000

    var body: some View {
        @Bindable var model = model
        NavigationSplitView(columnVisibility: $columnVisibility) {
            SidebarView(selection: $model.selection)
                .navigationSplitViewColumnWidth(min: 180, ideal: 210, max: 280)
        } detail: {
            DetailColumn(selection: model.selection ?? .dashboard)
                // Bound the ideal width: greedy content (flow layouts, canvases)
                // would otherwise claim its ideal and collapse the sidebar or inspector.
                .frame(minWidth: 420, idealWidth: 720, maxWidth: .infinity, maxHeight: .infinity)
                .background(Theme.background)
        }
        // On the split view rather than the detail column, so the inspector stays
        // open when a navigation stack in the detail column pushes a new view.
        .inspector(isPresented: $model.isInspectorPresented) {
            InspectorView(item: model.inspector)
                .inspectorColumnWidth(min: 260, ideal: 320, max: 420)
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
        .onGeometryChange(for: CGFloat.self) { proxy in proxy.size.width } action: { width in
            windowWidth = width
            fitColumns(mayRestoreSidebar: true)
        }
        .onChange(of: model.isInspectorPresented) { fitColumns(mayRestoreSidebar: false) }
    }

    /// Narrow windows hide the sidebar while the inspector is open, the way Mail
    /// does. The sidebar only comes back on its own when the window gets wider:
    /// showing it in a narrow window makes AppKit grow the window to fit it.
    private func fitColumns(mayRestoreSidebar: Bool) {
        let isCrowded = model.isInspectorPresented && windowWidth < Self.widthForAllColumns
        if isCrowded, columnVisibility != .detailOnly {
            columnVisibility = .detailOnly
            sidebarHiddenForInspector = true
        } else if !isCrowded, mayRestoreSidebar, sidebarHiddenForInspector {
            columnVisibility = .all
            sidebarHiddenForInspector = false
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

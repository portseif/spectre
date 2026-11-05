import SwiftUI

/// Identity correlation workspace: graph, filters, and relationship review.
struct IdentitiesView: View {
    @Environment(AppModel.self) private var model
    @State private var investigationID: UUID?
    @State private var filter = GraphFilter()
    @State private var selectedNode: UUID?

    private var completed: [Investigation] {
        model.investigations.filter { $0.status.isTerminal }
    }

    var body: some View {
        VStack(spacing: 0) {
            GraphControls(investigations: completed, investigationID: $investigationID, filter: $filter, selectedNode: selectedNode)
            Divider()
            if let investigationID, let session = model.session(for: investigationID) {
                IdentityWorkspace(session: session, filter: $filter, selectedNode: $selectedNode)
                    .task(id: investigationID) { await session.load() }
            } else {
                ContentUnavailableView("No investigation selected", systemImage: "point.3.connected.trianglepath.dotted", description: Text("Choose a completed investigation to explore its identity graph."))
            }
        }
        // Report a bounded minimum so the split view keeps room for the
        // sidebar and inspector (the canvas would otherwise claim its ideal).
        .frame(minWidth: 620, maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle("Identities")
        .onAppear {
            if investigationID == nil {
                investigationID = model.investigationPath.last ?? completed.first?.id
            }
        }
    }
}

private struct GraphControls: View {
    let investigations: [Investigation]
    @Binding var investigationID: UUID?
    @Binding var filter: GraphFilter
    let selectedNode: UUID?

    var body: some View {
        HStack(spacing: 12) {
            Picker("Investigation", selection: $investigationID) {
                Text("Choose investigation").tag(UUID?.none)
                ForEach(investigations) { investigation in
                    Text("\(investigation.target.value) · \(investigation.createdAt.formatted(date: .abbreviated, time: .shortened))")
                        .tag(UUID?.some(investigation.id))
                }
            }
            .labelsHidden()
            .frame(maxWidth: 320)
            Spacer()
            Menu {
                ForEach(IdentityKind.allCases) { kind in
                    Toggle(kind.label, isOn: Binding(
                        get: { !filter.hiddenKinds.contains(kind) },
                        set: { isVisible in
                            if isVisible { filter.hiddenKinds.remove(kind) } else { filter.hiddenKinds.insert(kind) }
                        }
                    ))
                }
                Divider()
                Picker("Minimum confidence", selection: $filter.minimumCategory) {
                    ForEach(ConfidenceCategory.allCases, id: \.self) { Text($0 == .unrelated ? "Show all" : "\($0.label) or stronger").tag($0) }
                }
            } label: {
                Label("Filter", systemImage: "line.3.horizontal.decrease.circle")
            }
            .fixedSize()
            Button {
                guard let selectedNode else { return }
                if filter.collapsed.contains(selectedNode) { filter.collapsed.remove(selectedNode) } else { filter.collapsed.insert(selectedNode) }
            } label: {
                Label(isSelectedCollapsed ? "Expand" : "Collapse", systemImage: isSelectedCollapsed ? "plus.circle" : "minus.circle")
            }
            .disabled(selectedNode == nil)
            .help("Collapse hides identities that connect only to the selected node")
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    private var isSelectedCollapsed: Bool {
        selectedNode.map { filter.collapsed.contains($0) } ?? false
    }
}

private struct IdentityWorkspace: View {
    @Environment(AppModel.self) private var model
    let session: InvestigationViewModel
    @Binding var filter: GraphFilter
    @Binding var selectedNode: UUID?

    var body: some View {
        HStack(spacing: 0) {
            IdentityGraphView(
                graph: session.graph,
                filter: $filter,
                selectedNode: $selectedNode,
                onSelectNode: { node in
                    if let findingID = node.findingId, let finding = session.findings.first(where: { $0.id == findingID }) {
                        model.inspector = .finding(finding)
                    } else {
                        model.inspector = .identity(node)
                    }
                },
                onSelectEdge: { edge in
                    let nodes = session.graph.nodes
                    model.inspector = .relationship(edge, source: nodes.first { $0.id == edge.sourceIdentity }, target: nodes.first { $0.id == edge.targetIdentity })
                }
            )
            .frame(minWidth: 280, maxWidth: .infinity, maxHeight: .infinity)
            Divider()
            RelationshipList(session: session)
                .frame(width: 340)
        }
    }
}

#Preview {
    NavigationStack {
        IdentitiesView()
    }
    .environment(AppModel(engine: PreviewEngine()))
    .frame(width: 1100, height: 700)
}

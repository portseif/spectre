import SwiftUI

/// Interactive identity graph: zoom (pinch or buttons), pan (drag), select
/// nodes and edges (click), filter by kind and confidence, collapse leaves.
struct IdentityGraphView: View {
    let graph: IdentityGraph
    @Binding var filter: GraphFilter
    @Binding var selectedNode: UUID?
    var onSelectNode: (Identity) -> Void = { _ in }
    var onSelectEdge: (IdentityRelationship) -> Void = { _ in }

    @State private var positions: [UUID: CGPoint] = [:]
    @State private var scale: CGFloat = 1
    @State private var committedScale: CGFloat = 1
    @State private var offset: CGSize = .zero
    @State private var committedOffset: CGSize = .zero

    private var visible: IdentityGraph { filter.visibleGraph(graph) }

    var body: some View {
        let visible = visible
        GeometryReader { geometry in
            let center = CGPoint(x: geometry.size.width / 2 + offset.width, y: geometry.size.height / 2 + offset.height)
            Canvas { context, _ in
                draw(visible, in: &context, center: center)
            }
            .contentShape(.rect)
            .gesture(panGesture)
            .simultaneousGesture(zoomGesture)
            .simultaneousGesture(
                SpatialTapGesture().onEnded { value in
                    select(at: value.location, center: center, graph: visible)
                }
            )
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(Text("Identity graph with \(visible.nodes.count) identities and \(visible.edges.count) relationships"))
            .accessibilityHint(Text("The relationship list beside the graph lists every relationship"))
        }
        .background(Theme.background)
        .overlay(alignment: .bottomTrailing) { zoomControls.padding(12) }
        .overlay(alignment: .bottomLeading) { GraphLegend().padding(12) }
        .task(id: LayoutKey(nodes: visible.nodes.map(\.id), edges: visible.edges.map(\.id))) {
            await relayout(visible)
        }
    }

    // MARK: Layout

    private func relayout(_ graph: IdentityGraph) async {
        let layout = GraphLayout(
            nodes: graph.nodes.map(\.id),
            edges: graph.edges.map { GraphLayout.Edge(source: $0.sourceIdentity, target: $0.targetIdentity, weight: $0.confidence) },
            pinned: graph.nodes.first { $0.isTarget }?.id
        )
        let computed = await Task.detached(priority: .userInitiated) { layout.positions() }.value
        withAnimation(.smooth(duration: 0.35)) { positions = computed }
    }

    private func screenPoint(_ id: UUID, center: CGPoint) -> CGPoint? {
        guard let point = positions[id] else { return nil }
        return CGPoint(x: center.x + point.x * scale, y: center.y + point.y * scale)
    }

    // MARK: Drawing

    private func draw(_ graph: IdentityGraph, in context: inout GraphicsContext, center: CGPoint) {
        for edge in graph.edges {
            guard let from = screenPoint(edge.sourceIdentity, center: center), let to = screenPoint(edge.targetIdentity, center: center) else { continue }
            var path = Path()
            path.move(to: from)
            path.addLine(to: to)
            let color = Theme.color(for: edge.category)
            let dashed = edge.category <= .weakEvidence
            let style = StrokeStyle(lineWidth: 1 + edge.confidence * 2.5, lineCap: .round, dash: dashed ? [5, 5] : [])
            context.stroke(path, with: .color(color.opacity(edge.category == .unrelated ? 0.25 : 0.75)), style: style)
        }
        for node in graph.nodes {
            guard let point = screenPoint(node.id, center: center) else { continue }
            let radius: CGFloat = (node.isTarget ? 16 : 10) * max(0.7, min(scale, 1.6))
            let circle = Path(ellipseIn: CGRect(x: point.x - radius, y: point.y - radius, width: radius * 2, height: radius * 2))
            let color = Theme.color(for: node.kind)
            context.fill(circle, with: .color(color.opacity(node.findingId == nil && !node.isTarget ? 0.45 : 1)))
            if node.verified || node.isTarget {
                let ring = Path(ellipseIn: CGRect(x: point.x - radius - 4, y: point.y - radius - 4, width: (radius + 4) * 2, height: (radius + 4) * 2))
                context.stroke(ring, with: .color(node.verified ? Theme.success : Theme.accent), lineWidth: 2)
            }
            if node.id == selectedNode {
                let halo = Path(ellipseIn: CGRect(x: point.x - radius - 7, y: point.y - radius - 7, width: (radius + 7) * 2, height: (radius + 7) * 2))
                context.stroke(halo, with: .color(Theme.primaryText), style: StrokeStyle(lineWidth: 1.5, dash: [3, 3]))
            }
            if filter.collapsed.contains(node.id) {
                context.draw(Text("+").font(.caption.bold()).foregroundStyle(Theme.primaryText), at: point)
            }
            let label = Text(node.label).font(.system(size: 11, weight: node.isTarget ? .semibold : .regular)).foregroundStyle(Theme.primaryText)
            context.draw(label, at: CGPoint(x: point.x, y: point.y + radius + 10), anchor: .top)
        }
    }

    // MARK: Interaction

    private var panGesture: some Gesture {
        DragGesture(minimumDistance: 4)
            .onChanged { value in
                offset = CGSize(width: committedOffset.width + value.translation.width, height: committedOffset.height + value.translation.height)
            }
            .onEnded { _ in committedOffset = offset }
    }

    private var zoomGesture: some Gesture {
        MagnifyGesture()
            .onChanged { value in scale = min(max(committedScale * value.magnification, 0.25), 4) }
            .onEnded { _ in committedScale = scale }
    }

    private func select(at location: CGPoint, center: CGPoint, graph: IdentityGraph) {
        let hit = graph.nodes.min { lhs, rhs in
            distance(location, screenPoint(lhs.id, center: center)) < distance(location, screenPoint(rhs.id, center: center))
        }
        if let hit, distance(location, screenPoint(hit.id, center: center)) < 20 {
            selectedNode = hit.id
            onSelectNode(hit)
            return
        }
        for edge in graph.edges {
            guard let from = screenPoint(edge.sourceIdentity, center: center), let to = screenPoint(edge.targetIdentity, center: center) else { continue }
            if distanceToSegment(location, from, to) < 6 {
                selectedNode = nil
                onSelectEdge(edge)
                return
            }
        }
        selectedNode = nil
    }

    private func distance(_ point: CGPoint, _ other: CGPoint?) -> CGFloat {
        guard let other else { return .infinity }
        return hypot(point.x - other.x, point.y - other.y)
    }

    private func distanceToSegment(_ point: CGPoint, _ start: CGPoint, _ end: CGPoint) -> CGFloat {
        let dx = end.x - start.x, dy = end.y - start.y
        let lengthSquared = dx * dx + dy * dy
        guard lengthSquared > 0 else { return distance(point, start) }
        let t = max(0, min(1, ((point.x - start.x) * dx + (point.y - start.y) * dy) / lengthSquared))
        return distance(point, CGPoint(x: start.x + t * dx, y: start.y + t * dy))
    }

    private var zoomControls: some View {
        HStack(spacing: 4) {
            Button { setScale(scale / 1.25) } label: { Image(systemName: "minus.magnifyingglass") }
                .accessibilityLabel(Text("Zoom out"))
            Button { resetView() } label: { Image(systemName: "arrow.up.left.and.down.right.magnifyingglass") }
                .accessibilityLabel(Text("Reset zoom"))
            Button { setScale(scale * 1.25) } label: { Image(systemName: "plus.magnifyingglass") }
                .accessibilityLabel(Text("Zoom in"))
        }
        .buttonStyle(.bordered)
        .padding(6)
        .background(.regularMaterial, in: .rect(cornerRadius: 8))
    }

    private func setScale(_ value: CGFloat) {
        withAnimation(.smooth) {
            scale = min(max(value, 0.25), 4)
            committedScale = scale
        }
    }

    private func resetView() {
        withAnimation(.smooth) {
            scale = 1
            committedScale = 1
            offset = .zero
            committedOffset = .zero
        }
    }
}

private struct LayoutKey: Equatable {
    let nodes: [UUID]
    let edges: [UUID]
}

private struct GraphLegend: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            ForEach(IdentityKind.allCases) { kind in
                HStack(spacing: 6) {
                    Circle().fill(Theme.color(for: kind)).frame(width: 8, height: 8)
                    Text(kind.label)
                }
            }
            HStack(spacing: 6) {
                Rectangle().fill(Theme.color(for: .strongEvidence)).frame(width: 16, height: 2)
                Text("Solid: possible or stronger")
            }
            HStack(spacing: 6) {
                Rectangle().stroke(Theme.color(for: .weakEvidence), style: StrokeStyle(lineWidth: 2, dash: [3, 3])).frame(width: 16, height: 2)
                Text("Dashed: weak evidence")
            }
        }
        .font(.caption2)
        .fixedSize()
        .padding(8)
        .background(.regularMaterial, in: .rect(cornerRadius: 8))
        .accessibilityHidden(true)
    }
}

#Preview {
    @Previewable @State var filter = GraphFilter()
    @Previewable @State var selected: UUID?
    IdentityGraphView(graph: PreviewData.graph, filter: $filter, selectedNode: $selected)
        .frame(width: 800, height: 600)
}

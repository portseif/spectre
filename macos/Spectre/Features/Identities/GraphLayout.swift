import CoreGraphics
import Foundation

/// Deterministic Fruchterman-Reingold layout. Pure value computation so it can
/// run off the main actor; identical input produces identical positions.
struct GraphLayout: Sendable {
    struct Edge: Sendable {
        let source: UUID
        let target: UUID
        let weight: Double
    }

    let nodes: [UUID]
    let edges: [Edge]
    let pinned: UUID?

    func positions(iterations: Int = 300, size: CGSize = CGSize(width: 1000, height: 800)) -> [UUID: CGPoint] {
        guard !nodes.isEmpty else { return [:] }
        let count = Double(nodes.count)
        let area = Double(size.width * size.height)
        let ideal = (area / count).squareRoot() * 0.6
        let index = Dictionary(uniqueKeysWithValues: nodes.enumerated().map { ($1, $0) })

        // Seed on a circle (deterministic), target in the centre.
        var position = nodes.enumerated().map { offset, identifier -> SIMD2<Double> in
            if identifier == pinned { return .zero }
            let angle = Double(offset) / count * 2 * .pi
            let radius = Double(min(size.width, size.height)) * 0.35
            return SIMD2(cos(angle) * radius, sin(angle) * radius)
        }
        let links = edges.compactMap { edge -> (Int, Int, Double)? in
            guard let source = index[edge.source], let target = index[edge.target] else { return nil }
            return (source, target, edge.weight)
        }

        var temperature = Double(size.width) / 8
        let cooling = temperature / Double(iterations + 1)
        for _ in 0..<iterations {
            var displacement = [SIMD2<Double>](repeating: .zero, count: nodes.count)
            for first in 0..<nodes.count {
                for second in (first + 1)..<nodes.count {
                    var delta = position[first] - position[second]
                    var distance = (delta * delta).sum().squareRoot()
                    if distance < 0.01 {
                        delta = SIMD2(0.01 * Double(first + 1), 0.01 * Double(second + 1))
                        distance = 0.02
                    }
                    let repulsion = (ideal * ideal) / distance
                    let push = delta / distance * repulsion
                    displacement[first] += push
                    displacement[second] -= push
                }
            }
            for (source, target, weight) in links {
                let delta = position[source] - position[target]
                let distance = max((delta * delta).sum().squareRoot(), 0.01)
                // Stronger evidence pulls nodes closer together.
                let attraction = (distance * distance) / ideal * (0.6 + weight)
                let pull = delta / distance * attraction
                displacement[source] -= pull
                displacement[target] += pull
            }
            for node in 0..<nodes.count where nodes[node] != pinned {
                let length = max((displacement[node] * displacement[node]).sum().squareRoot(), 0.01)
                position[node] += displacement[node] / length * min(length, temperature)
                // Gentle gravity keeps disconnected components on screen.
                position[node] *= 0.995
            }
            temperature = max(temperature - cooling, 1)
        }

        return Dictionary(uniqueKeysWithValues: nodes.enumerated().map { offset, identifier in
            (identifier, CGPoint(x: position[offset].x, y: position[offset].y))
        })
    }
}

/// Visibility rules for the graph: kind filters, minimum confidence, and
/// collapsed nodes (which hide neighbours that connect only to them).
struct GraphFilter: Equatable, Sendable {
    var hiddenKinds: Set<IdentityKind> = []
    var minimumCategory: ConfidenceCategory = .unrelated
    var collapsed: Set<UUID> = []

    func visibleGraph(_ graph: IdentityGraph) -> IdentityGraph {
        let edges = graph.edges.filter { $0.category >= minimumCategory }
        var nodes = graph.nodes.filter { !hiddenKinds.contains($0.kind) || $0.isTarget }
        var visibleIDs = Set(nodes.map(\.id))
        var degree: [UUID: Int] = [:]
        for edge in edges where visibleIDs.contains(edge.sourceIdentity) && visibleIDs.contains(edge.targetIdentity) {
            degree[edge.sourceIdentity, default: 0] += 1
            degree[edge.targetIdentity, default: 0] += 1
        }
        var hidden: Set<UUID> = []
        for collapsedID in collapsed {
            for edge in edges {
                let neighbour: UUID? = edge.sourceIdentity == collapsedID ? edge.targetIdentity : (edge.targetIdentity == collapsedID ? edge.sourceIdentity : nil)
                if let neighbour, degree[neighbour] == 1, !(graph.nodes.first { $0.id == neighbour }?.isTarget ?? false) {
                    hidden.insert(neighbour)
                }
            }
        }
        nodes.removeAll { hidden.contains($0.id) }
        visibleIDs = Set(nodes.map(\.id))
        // Drop nodes left without any visible edge when filtering by confidence.
        let visibleEdges = edges.filter { visibleIDs.contains($0.sourceIdentity) && visibleIDs.contains($0.targetIdentity) }
        if minimumCategory > .unrelated {
            let connected = Set(visibleEdges.flatMap { [$0.sourceIdentity, $0.targetIdentity] })
            nodes.removeAll { !$0.isTarget && !connected.contains($0.id) }
        }
        return IdentityGraph(nodes: nodes, edges: visibleEdges)
    }

    /// Number of neighbours a collapse would hide (for button state).
    func collapsibleCount(of nodeID: UUID, in graph: IdentityGraph) -> Int {
        var expanded = self
        expanded.collapsed.remove(nodeID)
        var collapsedFilter = self
        collapsedFilter.collapsed.insert(nodeID)
        return expanded.visibleGraph(graph).nodes.count - collapsedFilter.visibleGraph(graph).nodes.count
    }
}

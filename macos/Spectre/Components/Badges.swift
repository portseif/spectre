import SwiftUI

/// Small capsule label with a tinted background.
struct TagChip: View {
    let text: String
    var tint: Color = Theme.secondaryText
    var symbol: String?

    var body: some View {
        HStack(spacing: 4) {
            if let symbol {
                Image(systemName: symbol).imageScale(.small).accessibilityHidden(true)
            }
            Text(text).lineLimit(1)
        }
        .font(.caption.weight(.medium))
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .foregroundStyle(tint)
        .background(tint.opacity(0.14), in: .capsule)
    }
}

struct ConfidenceBadge: View {
    let category: ConfidenceCategory

    var body: some View {
        TagChip(text: category.label, tint: Theme.color(for: category), symbol: symbol)
            .accessibilityLabel(Text("Confidence: \(category.label)"))
    }

    private var symbol: String {
        switch category {
        case .confirmed: "checkmark.seal.fill"
        case .strongEvidence: "link.circle.fill"
        case .possible: "questionmark.circle"
        case .weakEvidence: "circle.dotted"
        case .unrelated: "xmark.circle"
        }
    }
}

struct StatusBadge: View {
    let status: InvestigationStatus

    var body: some View {
        TagChip(text: status.label, tint: Theme.color(for: status), symbol: symbol)
            .accessibilityLabel(Text("Status: \(status.label)"))
    }

    private var symbol: String {
        switch status {
        case .pending: "clock"
        case .running: "bolt.horizontal.circle"
        case .completed: "checkmark.circle.fill"
        case .partiallyCompleted: "exclamationmark.circle"
        case .failed: "xmark.octagon.fill"
        case .cancelled: "stop.circle"
        }
    }
}

struct RiskBadge: View {
    let level: RiskLevel

    var body: some View {
        TagChip(text: "\(level.label) risk", tint: Theme.color(for: level), symbol: "shield.lefthalf.filled")
    }
}

struct VerificationBadge: View {
    let status: VerificationStatus

    var body: some View {
        TagChip(text: status.label, tint: tint, symbol: symbol)
    }

    private var tint: Color {
        switch status {
        case .ownershipVerified: Theme.success
        case .ownershipPending: Theme.warning
        case .publiclyObserved: Theme.secondaryAccent
        case .unverified: Theme.secondaryText
        }
    }

    private var symbol: String {
        switch status {
        case .ownershipVerified: "checkmark.shield.fill"
        case .ownershipPending: "hourglass"
        case .publiclyObserved: "eye"
        case .unverified: "questionmark.diamond"
        }
    }
}

/// Big-number tile for the dashboard.
struct MetricTile: View {
    let title: LocalizedStringKey
    let value: String
    let symbol: String
    var tint: Color = Theme.accent

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 8) {
                Label(title, systemImage: symbol)
                    .font(.subheadline)
                    .foregroundStyle(.spectreSecondary)
                    .labelStyle(TintedIconLabelStyle(tint: tint))
                Text(value)
                    .font(.system(size: 28, weight: .semibold, design: .rounded).monospacedDigit())
                    .contentTransition(.numericText())
            }
        }
        .accessibilityElement(children: .combine)
    }
}

struct TintedIconLabelStyle: LabelStyle {
    let tint: Color

    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 6) {
            configuration.icon.foregroundStyle(tint)
            configuration.title
        }
    }
}

struct KeyValueRow: View {
    let label: LocalizedStringKey
    let value: String

    var body: some View {
        LabeledContent(label) {
            Text(value)
                .textSelection(.enabled)
                .multilineTextAlignment(.trailing)
        }
        .font(.callout)
    }
}

/// Wrapping horizontal layout for chips.
struct FlowLayout: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let rows = arrange(width: proposal.width ?? .infinity, subviews: subviews)
        let height = rows.last.map { $0.y + $0.height } ?? 0
        let width = rows.map(\.width).max() ?? 0
        return CGSize(width: proposal.width ?? width, height: height)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        for row in arrange(width: bounds.width, subviews: subviews) {
            var x = bounds.minX
            for index in row.indices {
                let size = subviews[index].sizeThatFits(.unspecified)
                subviews[index].place(at: CGPoint(x: x, y: bounds.minY + row.y), proposal: ProposedViewSize(size))
                x += size.width + spacing
            }
        }
    }

    private struct Row {
        var indices: [Int] = []
        var y: CGFloat = 0
        var width: CGFloat = 0
        var height: CGFloat = 0
    }

    private func arrange(width: CGFloat, subviews: Subviews) -> [Row] {
        var rows: [Row] = [Row()]
        for index in subviews.indices {
            let size = subviews[index].sizeThatFits(.unspecified)
            if !rows[rows.count - 1].indices.isEmpty, rows[rows.count - 1].width + spacing + size.width > width {
                let previous = rows[rows.count - 1]
                rows.append(Row(y: previous.y + previous.height + spacing))
            }
            let current = rows.count - 1
            rows[current].width += (rows[current].indices.isEmpty ? 0 : spacing) + size.width
            rows[current].height = max(rows[current].height, size.height)
            rows[current].indices.append(index)
        }
        return rows
    }
}

#Preview("Badges") {
    VStack(alignment: .leading, spacing: 12) {
        FlowLayout {
            ForEach(ConfidenceCategory.allCases, id: \.self) { ConfidenceBadge(category: $0) }
        }
        HStack { StatusBadge(status: .running); StatusBadge(status: .partiallyCompleted); RiskBadge(level: .high) }
        HStack { VerificationBadge(status: .ownershipVerified); VerificationBadge(status: .publiclyObserved) }
        MetricTile(title: "Findings", value: "128", symbol: "sparkle.magnifyingglass")
        KeyValueRow(label: "Registrar", value: "MarkMonitor Inc.")
    }
    .padding()
    .frame(width: 420)
}

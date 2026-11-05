import SwiftUI

/// Rounded surface container used throughout the dashboard.
struct Card<Content: View>: View {
    private let padding: CGFloat
    private let content: Content

    init(padding: CGFloat = Theme.spacing, @ViewBuilder content: () -> Content) {
        self.padding = padding
        self.content = content()
    }

    var body: some View {
        content
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Theme.surface, in: .rect(cornerRadius: Theme.cornerRadius))
            .overlay {
                RoundedRectangle(cornerRadius: Theme.cornerRadius).strokeBorder(Theme.border, lineWidth: 1)
            }
    }
}

/// Section title with an optional count.
struct SectionHeader: View {
    let title: LocalizedStringKey
    let symbol: String
    var count: Int?

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: symbol)
                .foregroundStyle(Theme.accent)
                .accessibilityHidden(true)
            Text(title)
                .font(.headline)
            if let count {
                Text(count, format: .number)
                    .font(.caption.monospacedDigit())
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Theme.elevated, in: .capsule)
                    .accessibilityLabel(Text("\(count) items"))
            }
            Spacer(minLength: 0)
        }
    }
}

#Preview("Card") {
    Card {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeader(title: "Public Profiles", symbol: "person.crop.circle", count: 12)
            Text("Card content").foregroundStyle(.spectreSecondary)
        }
    }
    .padding()
    .frame(width: 360)
}

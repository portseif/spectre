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
            .background(Theme.surface, in: .rect(cornerRadius: Theme.cornerRadius, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: Theme.cornerRadius, style: .continuous)
                    .strokeBorder(Theme.border.opacity(0.7), lineWidth: 1)
            }
    }
}

/// Background for controls that float over content, such as the graph's
/// zoom buttons and legend: Liquid Glass on macOS 26, a material before that.
private struct FloatingPanelBackground: ViewModifier {
    func body(content: Content) -> some View {
        if #available(macOS 26.0, *) {
            content.glassEffect(.regular, in: .rect(cornerRadius: 12, style: .continuous))
        } else {
            content.background(.regularMaterial, in: .rect(cornerRadius: 12, style: .continuous))
        }
    }
}

extension View {
    func floatingPanel() -> some View {
        modifier(FloatingPanelBackground())
    }
}

/// Row or card button with fluid press feedback: it dips slightly on press
/// and springs back. Honors Reduce Motion by dropping the scale.
struct PressableRowStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        PressableRow(configuration: configuration)
    }

    private struct PressableRow: View {
        let configuration: ButtonStyleConfiguration
        @Environment(\.accessibilityReduceMotion) private var reduceMotion

        var body: some View {
            configuration.label
                .contentShape(.rect)
                .scaleEffect(configuration.isPressed && !reduceMotion ? 0.985 : 1)
                .opacity(configuration.isPressed ? 0.82 : 1)
                .animation(reduceMotion ? .easeOut(duration: 0.1) : .snappy(duration: 0.22, extraBounce: 0.1), value: configuration.isPressed)
        }
    }
}

extension ButtonStyle where Self == PressableRowStyle {
    static var pressableRow: PressableRowStyle { PressableRowStyle() }
}

extension View {
    /// Negative tracking for large display text. Apple tightens letters as they
    /// grow, since the same spacing reads too loose at display sizes. Body text
    /// is left near zero, so only apply this to titles.
    func displayTracking() -> some View { tracking(-0.4) }
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

#Preview("Floating panel") {
    Label("Zoom", systemImage: "plus.magnifyingglass")
        .padding(10)
        .floatingPanel()
        .padding(40)
        .background(Theme.background)
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

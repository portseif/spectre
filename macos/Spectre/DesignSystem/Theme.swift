import AppKit
import SwiftUI

/// Spectre's palette: dark-first with a matching light variant.
enum Theme {
    private static func adaptive(dark: UInt32, light: UInt32) -> Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            let isDark = appearance.bestMatch(from: [.darkAqua, .aqua, .vibrantDark, .vibrantLight]).map { $0 == .darkAqua || $0 == .vibrantDark } ?? true
            return NSColor(hex: isDark ? dark : light)
        })
    }

    static let background = adaptive(dark: 0x090B10, light: 0xF5F6F9)
    static let sidebar = adaptive(dark: 0x10131A, light: 0xECEEF3)
    static let surface = adaptive(dark: 0x171B24, light: 0xFFFFFF)
    static let elevated = adaptive(dark: 0x202633, light: 0xF0F2F6)
    static let border = adaptive(dark: 0x2A3140, light: 0xDDE1E8)
    static let primaryText = adaptive(dark: 0xF8FAFC, light: 0x0F172A)
    static let secondaryText = adaptive(dark: 0x94A3B8, light: 0x5B6576)

    static let accent = Color(nsColor: NSColor(hex: 0x7C5CFF))
    static let secondaryAccent = Color(nsColor: NSColor(hex: 0x38BDF8))
    static let success = Color(nsColor: NSColor(hex: 0x22C55E))
    static let warning = Color(nsColor: NSColor(hex: 0xF59E0B))
    static let danger = Color(nsColor: NSColor(hex: 0xEF4444))

    static let cornerRadius: CGFloat = 10
    static let spacing: CGFloat = 16

    static func color(for category: ConfidenceCategory) -> Color {
        switch category {
        case .confirmed: success
        case .strongEvidence: secondaryAccent
        case .possible: accent
        case .weakEvidence: warning
        case .unrelated: secondaryText
        }
    }

    static func color(for status: InvestigationStatus) -> Color {
        switch status {
        case .pending: secondaryText
        case .running: secondaryAccent
        case .completed: success
        case .partiallyCompleted: warning
        case .failed: danger
        case .cancelled: secondaryText
        }
    }

    static func color(for risk: RiskLevel) -> Color {
        switch risk {
        case .none: success
        case .low: secondaryAccent
        case .medium: warning
        case .high, .critical: danger
        }
    }

    static func color(for strength: HashStrength) -> Color {
        switch strength {
        case .strong: success
        case .acceptable: secondaryAccent
        case .weak: warning
        case .critical: danger
        case .unknown: secondaryText
        }
    }

    static func color(for kind: IdentityKind) -> Color {
        switch kind {
        case .username: accent
        case .profile: secondaryAccent
        case .email: success
        case .phone: Color(nsColor: NSColor(hex: 0xE879F9))
        case .domain: Color(nsColor: NSColor(hex: 0xFB923C))
        case .website: secondaryText
        case .breach: danger
        }
    }
}

extension NSColor {
    convenience init(hex: UInt32) {
        self.init(
            srgbRed: CGFloat((hex >> 16) & 0xFF) / 255,
            green: CGFloat((hex >> 8) & 0xFF) / 255,
            blue: CGFloat(hex & 0xFF) / 255,
            alpha: 1
        )
    }
}

extension ShapeStyle where Self == Color {
    static var spectreSecondary: Color { Theme.secondaryText }
}

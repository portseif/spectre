import AppKit
import CoreText
import Foundation

/// Builds the investigation PDF report with Core Text pagination.
///
/// The report separates *confirmed findings* (directly observed facts,
/// ownership-verified or investigator-confirmed relationships) from *inferred
/// associations*, and lists every evidence source.
enum ReportGenerator {
    private static let pageSize = CGSize(width: 612, height: 792) // US Letter
    private static let margin: CGFloat = 54

    static func pdf(for detail: InvestigationDetail, generatedAt: Date = .now) -> Data {
        let text = attributedReport(for: detail, generatedAt: generatedAt)
        let data = NSMutableData()
        var mediaBox = CGRect(origin: .zero, size: pageSize)
        guard let consumer = CGDataConsumer(data: data as CFMutableData),
              let context = CGContext(consumer: consumer, mediaBox: &mediaBox, [
                  kCGPDFContextTitle: "Spectre report – \(detail.investigation.target.value)",
                  kCGPDFContextCreator: "Spectre \(Bundle.main.shortVersion)",
              ] as CFDictionary)
        else { return Data() }

        let framesetter = CTFramesetterCreateWithAttributedString(text as CFAttributedString)
        let body = CGRect(x: margin, y: margin + 18, width: pageSize.width - margin * 2, height: pageSize.height - margin * 2 - 18)
        var location = 0
        var page = 1
        repeat {
            context.beginPDFPage(nil)
            let frame = CTFramesetterCreateFrame(framesetter, CFRange(location: location, length: 0), CGPath(rect: body, transform: nil), nil)
            CTFrameDraw(frame, context)
            let visible = CTFrameGetVisibleStringRange(frame)
            drawFooter(in: context, page: page, target: detail.investigation.target.value)
            context.endPDFPage()
            if visible.length == 0 { break }
            location += visible.length
            page += 1
        } while location < text.length
        context.closePDF()
        return data as Data
    }

    private static func drawFooter(in context: CGContext, page: Int, target: String) {
        let footer = NSAttributedString(string: "Spectre · Confidential investigation report · \(target) · Page \(page)", attributes: [
            .font: NSFont.systemFont(ofSize: 8),
            .foregroundColor: NSColor.gray,
        ])
        let line = CTLineCreateWithAttributedString(footer)
        context.textPosition = CGPoint(x: margin, y: margin - 20)
        CTLineDraw(line, context)
    }

    // MARK: Content

    static func attributedReport(for detail: InvestigationDetail, generatedAt: Date) -> NSAttributedString {
        let builder = Builder()
        let investigation = detail.investigation
        let nodes = Dictionary(uniqueKeysWithValues: detail.graph.nodes.map { ($0.id, $0) })
        let profiles = detail.findings.compactMap { finding -> (Finding, ProfileFinding)? in
            if case .profile(let profile) = finding.data { return (finding, profile) }
            return nil
        }
        let breaches = detail.findings.compactMap { finding -> BreachFinding? in
            if case .breachIncident(let breach) = finding.data { return breach }
            return nil
        }
        let confirmedEdges = detail.graph.edges.filter { $0.category == .confirmed }
        let inferredEdges = detail.graph.edges.filter { $0.category != .confirmed && $0.category != .unrelated }
        let rejectedEdges = detail.graph.edges.filter { $0.category == .unrelated }

        builder.title("Spectre Investigation Report")
        builder.caption("Generated \(generatedAt.formatted(date: .long, time: .standard)) · Investigation \(investigation.id.uuidString.lowercased())")

        builder.heading("1. Investigation summary")
        builder.field("Status", investigation.status.label)
        builder.field("Findings", "\(detail.findings.count) (\(detail.findings.filter { !$0.isInferredAssociation }.count) observed facts, \(detail.findings.filter(\.isInferredAssociation).count) inferred associations)")
        builder.field("Relationships", "\(confirmedEdges.count) confirmed · \(inferredEdges.count) inferred · \(rejectedEdges.count) rejected")
        builder.field("Providers", investigation.providers.joined(separator: ", "))
        if !investigation.errors.isEmpty {
            builder.field("Provider errors", investigation.errors.map { "\($0.providerId): \($0.message)" }.joined(separator: "; "))
        }
        builder.field("Authorization & scope", investigation.purpose)

        builder.heading("2. Target information")
        builder.field("Target type", investigation.targetType.label)
        builder.field("Normalized value", investigation.target.value)
        for finding in detail.findings {
            switch finding.data {
            case .phoneMetadata(let phone):
                builder.field("Numbering plan", "\(phone.internationalFormat) · region \(phone.regionCode ?? "non-geographic") · \(phone.numberType)")
            case .emailIntelligence(let mail):
                builder.field("Mail domain", "\(mail.domain) · accepts mail: \(mail.acceptsMail ? "yes" : "no") · SPF: \(mail.spf ?? "none") · DMARC: \(mail.dmarc ?? "none")")
            case .domainRegistration(let registration):
                builder.field("Registration", "\(registration.registrar ?? "registrar not disclosed") · registered \(registration.registeredAt ?? "?") · expires \(registration.expiresAt ?? "?")")
            default: break
            }
        }

        builder.heading("3. Public profiles discovered")
        if profiles.isEmpty { builder.paragraph("No public profiles were found.") }
        for (finding, profile) in profiles {
            builder.bullet("\(profile.platform) — \(profile.username) [\(finding.confidence.category.label)]", detail: profile.profileUrl)
        }

        builder.heading("4. Confirmed identity associations")
        builder.paragraph("Confirmed means ownership was verified or an investigator confirmed the association after reviewing evidence.", secondary: true)
        if confirmedEdges.isEmpty { builder.paragraph("None.") }
        for edge in confirmedEdges {
            builder.bullet("\(nodes[edge.sourceIdentity]?.label ?? "?") → \(nodes[edge.targetIdentity]?.label ?? "?") (\(edge.relationship.label))", detail: edge.evidence.map(\.description).joined(separator: "; "))
        }

        builder.heading("5. Inferred associations (not confirmed)")
        builder.paragraph("These relationships rest on public evidence such as matching usernames or explicit links. They are not proof of common ownership.", secondary: true)
        if inferredEdges.isEmpty { builder.paragraph("None.") }
        for edge in inferredEdges.sorted(by: { $0.confidence > $1.confidence }) {
            builder.bullet(
                "\(nodes[edge.sourceIdentity]?.label ?? "?") → \(nodes[edge.targetIdentity]?.label ?? "?") — \(edge.category.label), score \(String(format: "%.2f", edge.confidence))",
                detail: edge.evidence.map(\.description).joined(separator: "; ")
            )
        }

        builder.heading("6. Known breach exposure")
        if breaches.isEmpty {
            builder.paragraph("No breach data is attached. Account-specific lookups require ownership verification.")
        }
        for breach in breaches {
            let subject = breach.exposedAccount.map { "\($0) in " } ?? "Service breach: "
            builder.bullet("\(subject)\(breach.incident.title) (\(breach.incident.breachDate ?? "date unknown"))", detail: "Data: \(breach.incident.dataClasses.joined(separator: ", ")). Source: \(breach.incident.source).")
        }
        if breaches.contains(where: { $0.incident.passwordDataExposed }) {
            builder.paragraph("A password-exposure indicator means the breach contained password data in some form; it does not prove a current password is compromised.", secondary: true)
        }

        builder.heading("7. Security findings")
        var securityFindings: [String] = []
        for finding in detail.findings {
            switch finding.data {
            case .dnsRecords(let dns): securityFindings += dns.observations
            case .emailIntelligence(let mail):
                if mail.spf == nil { securityFindings.append("\(mail.domain) publishes no SPF record") }
                if mail.dmarc == nil { securityFindings.append("\(mail.domain) publishes no DMARC policy") }
            case .webPresence(let web) where web.securityTxt == nil:
                securityFindings.append("No security.txt at \(web.url)")
            case .profile(let profile) where profile.publicEmail != nil:
                securityFindings.append("\(profile.platform) profile publicly discloses an email address")
            default: break
            }
        }
        if securityFindings.isEmpty { builder.paragraph("No security findings.") }
        securityFindings.forEach { builder.bullet($0) }

        builder.heading("8. Confidence classifications")
        builder.paragraph("Scores are explainable evidence weights combined as 1 − Π(1 − wᵢ), not calibrated probabilities.", secondary: true)
        for category in ConfidenceCategory.allCases.reversed() {
            let count = detail.findings.filter { $0.confidence.category == category }.count
            builder.field(category.label, "\(count) finding(s)")
        }

        builder.heading("9. Evidence sources")
        for finding in detail.findings {
            let sources = finding.sources.map { "\($0.providerName) (\($0.method.label)) \($0.url ?? "") at \(EngineDate.format($0.retrievedAt))" }
            builder.bullet(finding.title, detail: sources.joined(separator: "\n"))
        }

        builder.heading("10. Remediation recommendations")
        var recommendations: [String] = []
        if !securityFindings.isEmpty { recommendations.append("Address the security findings above (mail authentication, CAA, security.txt).") }
        if !breaches.isEmpty {
            recommendations.append("Change passwords for breached services and anywhere they were reused; use a password manager.")
            recommendations.append("Enable multi-factor authentication on affected accounts.")
        }
        if profiles.contains(where: { $0.1.publicEmail != nil }) {
            recommendations.append("Review whether publicly listed email addresses should remain public.")
        }
        recommendations.append("Review inferred associations and confirm or reject them before relying on this report.")
        recommendations.forEach { builder.bullet($0) }

        builder.heading("11. Investigation timestamps")
        builder.field("Created", EngineDate.format(investigation.createdAt))
        if let started = investigation.startedAt { builder.field("Started", EngineDate.format(started)) }
        if let completed = investigation.completedAt { builder.field("Completed", EngineDate.format(completed)) }
        if let metrics = investigation.metrics {
            builder.field("Duration", "\(metrics.totalDurationMs) ms (first finding after \(metrics.timeToFirstFindingMs.map { "\($0) ms" } ?? "—"))")
        }
        return builder.output
    }

    private struct Builder {
        let output = NSMutableAttributedString()

        private func paragraphStyle(spacingBefore: CGFloat = 0, indent: CGFloat = 0) -> NSParagraphStyle {
            let style = NSMutableParagraphStyle()
            style.paragraphSpacingBefore = spacingBefore
            style.paragraphSpacing = 4
            style.firstLineHeadIndent = indent
            style.headIndent = indent + (indent > 0 ? 10 : 0)
            style.lineBreakMode = .byWordWrapping
            return style
        }

        private func append(_ text: String, font: NSFont, color: NSColor = .black, style: NSParagraphStyle) {
            output.append(NSAttributedString(string: text + "\n", attributes: [.font: font, .foregroundColor: color, .paragraphStyle: style]))
        }

        func title(_ text: String) { append(text, font: .systemFont(ofSize: 22, weight: .bold), style: paragraphStyle()) }
        func caption(_ text: String) { append(text, font: .systemFont(ofSize: 9), color: .darkGray, style: paragraphStyle()) }
        func heading(_ text: String) {
            append(text, font: .systemFont(ofSize: 14, weight: .semibold), color: NSColor(hex: 0x4C35C9), style: paragraphStyle(spacingBefore: 14))
        }
        func paragraph(_ text: String, secondary: Bool = false) {
            append(text, font: .systemFont(ofSize: secondary ? 9 : 10), color: secondary ? .darkGray : .black, style: paragraphStyle())
        }
        func field(_ label: String, _ value: String) {
            let line = NSMutableAttributedString(string: "\(label): ", attributes: [.font: NSFont.systemFont(ofSize: 10, weight: .semibold), .foregroundColor: NSColor.black, .paragraphStyle: paragraphStyle()])
            line.append(NSAttributedString(string: value + "\n", attributes: [.font: NSFont.systemFont(ofSize: 10), .foregroundColor: NSColor.black, .paragraphStyle: paragraphStyle()]))
            output.append(line)
        }
        func bullet(_ text: String, detail: String? = nil) {
            append("• \(text)", font: .systemFont(ofSize: 10), style: paragraphStyle(indent: 8))
            if let detail, !detail.isEmpty {
                append(detail, font: .systemFont(ofSize: 8.5), color: .darkGray, style: paragraphStyle(indent: 18))
            }
        }
    }
}

extension Bundle {
    var shortVersion: String { infoDictionary?["CFBundleShortVersionString"] as? String ?? "dev" }
}

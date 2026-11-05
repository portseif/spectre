import SwiftUI

/// Right-hand inspector: provenance, confidence, evidence, and guidance for
/// the current selection.
struct InspectorView: View {
    let item: InspectorItem?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                switch item {
                case .none:
                    EmptyInspector()
                case .finding(let finding):
                    FindingInspector(finding: finding)
                case .relationship(let relationship, let source, let target):
                    RelationshipInspector(relationship: relationship, source: source, target: target)
                case .identity(let identity):
                    IdentityInspector(identity: identity)
                case .breach(let incident):
                    InspectorSection(title: "Breach") {
                        Text(incident.title).font(.title3.weight(.semibold))
                        BreachIncidentDetail(incident: incident)
                    }
                    InspectorSection(title: "Recommendations") {
                        RecommendationList(items: breachRecommendations(incident))
                    }
                }
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Theme.sidebar)
    }

    private func breachRecommendations(_ incident: BreachIncident) -> [String] {
        var items: [String] = []
        if incident.passwordDataExposed { items.append("If you used this service, change that password and any reuse of it.") }
        if incident.isStealerLog { items.append("Scan devices for information-stealing malware before rotating credentials.") }
        items.append("Enable multi-factor authentication wherever it is available.")
        return items
    }
}

private struct EmptyInspector: View {
    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: "sidebar.trailing")
                .font(.title2)
                .foregroundStyle(.spectreSecondary)
                .accessibilityHidden(true)
            Text("Nothing selected").font(.headline)
            Text("Select a finding, relationship, or graph node to see its evidence and provenance.")
                .font(.callout)
                .foregroundStyle(.spectreSecondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.top, 48)
    }
}

private struct InspectorSection<Content: View>: View {
    let title: LocalizedStringKey
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.caption.weight(.semibold)).textCase(.uppercase).foregroundStyle(.spectreSecondary)
            content
        }
    }
}

private struct RecommendationList: View {
    let items: [String]

    var body: some View {
        ForEach(items, id: \.self) { item in
            Label(item, systemImage: "checkmark.shield").font(.callout)
        }
    }
}

private struct FindingInspector: View {
    @Environment(AppModel.self) private var model
    let finding: Finding

    var body: some View {
        InspectorSection(title: "Finding") {
            Text(finding.title).font(.title3.weight(.semibold))
            if let summary = finding.summary { Text(summary).font(.callout).foregroundStyle(.spectreSecondary) }
            HStack {
                ConfidenceBadge(category: finding.confidence.category)
                VerificationBadge(status: finding.verificationStatus)
            }
            Text(finding.isInferredAssociation ? "Inferred association. It is not proof of common ownership." : "Directly observed fact.")
                .font(.caption)
                .foregroundStyle(.spectreSecondary)
        }
        InspectorSection(title: "Confidence") {
            LabeledContent("Evidence score") { Text(finding.confidence.score, format: .number.precision(.fractionLength(2))) }
                .font(.callout)
            ForEach(finding.confidence.rationale, id: \.self) { reason in
                Label(reason, systemImage: "text.magnifyingglass").font(.callout)
            }
            Text("Scores are explainable evidence weights, not calibrated probabilities.").font(.caption2).foregroundStyle(.spectreSecondary)
        }
        InspectorSection(title: "Details") {
            FindingDetailContent(data: finding.data)
        }
        InspectorSection(title: "Source & provenance") {
            KeyValueRow(label: "Discovered", value: finding.discoveredAt.formatted(date: .abbreviated, time: .standard))
            ForEach(finding.sources, id: \.self) { source in
                VStack(alignment: .leading, spacing: 2) {
                    Text("\(source.providerName) · \(source.method.label)").font(.callout.weight(.medium))
                    if let urlString = source.url {
                        if let url = URL(string: urlString), url.scheme?.hasPrefix("http") == true {
                            Link(urlString, destination: url).font(.caption).lineLimit(2)
                        } else {
                            Text(urlString).font(.caption.monospaced()).foregroundStyle(.spectreSecondary)
                        }
                    }
                    Text(source.retrievedAt.formatted(date: .omitted, time: .standard)).font(.caption2).foregroundStyle(.spectreSecondary)
                }
            }
        }
        AssociatedRecords(findingID: finding.id, investigationID: finding.investigationId)
        InspectorSection(title: "Security recommendations") {
            RecommendationList(items: recommendations)
        }
    }

    private var recommendations: [String] {
        switch finding.data {
        case .profile(let profile):
            var items = ["Confirm or reject this association in Identities before relying on it."]
            if profile.publicEmail != nil { items.append("The profile publishes an email address; verify ownership before any breach lookup.") }
            items.append("Review what this profile discloses publicly (location, links, contact details).")
            return items
        case .dnsRecords(let dns):
            return dns.observations.isEmpty ? ["DNS posture shows no obvious gaps."] : dns.observations.map { "Address: \($0)" }
        case .emailIntelligence(let intelligence):
            var items: [String] = []
            if intelligence.spf == nil { items.append("Publish an SPF record for \(intelligence.domain).") }
            if intelligence.dmarc == nil { items.append("Publish a DMARC policy (start with p=none and move to quarantine/reject).") }
            return items.isEmpty ? ["Mail authentication records are present."] : items
        case .breachIncident(let breach):
            return breach.incident.passwordDataExposed
                ? ["Change the password used on this service and anywhere it was reused.", "Enable multi-factor authentication."]
                : ["Be alert to phishing that references this service."]
        case .domainRegistration(let registration):
            return registration.dnssecSigned == false ? ["Consider enabling DNSSEC for the domain."] : ["No registration issues detected."]
        case .webPresence(let web):
            var items = (web.headerChecks ?? []).compactMap { check in check.note.map { "\(check.header): \($0)" } }
            if web.securityTxt == nil { items.append("Publish /.well-known/security.txt so researchers can report issues (RFC 9116).") }
            return items.isEmpty ? ["No issues found on the homepage response."] : items
        case .emailAssociation:
            return ["Verify mailbox ownership before account-specific lookups."]
        case .phoneMetadata:
            return ["Numbering metadata only; no subscriber lookups are performed."]
        case .certificates(let certificates):
            return ["Review the \(certificates.hostnames.count) logged hostnames for forgotten or unexpected services."]
        case .pgpKey:
            return ["Other addresses on the same key are strong leads. Start them as separate investigations if they are in scope."]
        case .webArchive:
            return ["Old captures can show contacts, staff pages, or links that have since been removed."]
        }
    }
}

private struct AssociatedRecords: View {
    @Environment(AppModel.self) private var model
    let findingID: UUID
    let investigationID: UUID

    var body: some View {
        if let graph = model.session(for: investigationID)?.graph,
           let node = graph.nodes.first(where: { $0.findingId == findingID }) {
            let related = graph.edges.filter { $0.sourceIdentity == node.id || $0.targetIdentity == node.id }
            if !related.isEmpty {
                InspectorSection(title: "Associated records") {
                    ForEach(related) { edge in
                        let otherID = edge.sourceIdentity == node.id ? edge.targetIdentity : edge.sourceIdentity
                        let other = graph.nodes.first { $0.id == otherID }
                        Button {
                            model.inspect(.relationship(edge, source: graph.nodes.first { $0.id == edge.sourceIdentity }, target: graph.nodes.first { $0.id == edge.targetIdentity }))
                        } label: {
                            HStack {
                                Text(other?.label ?? "Unknown").lineLimit(1)
                                Spacer()
                                ConfidenceBadge(category: edge.category)
                            }
                        }
                        .buttonStyle(.pressableRow)
                    }
                }
            }
        }
    }
}

private struct RelationshipInspector: View {
    let relationship: IdentityRelationship
    let source: Identity?
    let target: Identity?

    var body: some View {
        InspectorSection(title: "Relationship") {
            Text(relationship.relationship.label).font(.title3.weight(.semibold))
            HStack(spacing: 6) {
                Text(source?.label ?? "?").lineLimit(1)
                Image(systemName: "arrow.right").accessibilityLabel(Text("to"))
                Text(target?.label ?? "?").lineLimit(1)
            }
            .font(.callout)
            HStack {
                ConfidenceBadge(category: relationship.category)
                if relationship.verified { TagChip(text: "Verified", tint: Theme.success, symbol: "checkmark.seal") }
            }
            LabeledContent("Evidence score") { Text(relationship.confidence, format: .number.precision(.fractionLength(2))) }.font(.callout)
            if let decision = relationship.investigatorDecision {
                KeyValueRow(label: "Investigator decision", value: decision.rawValue.capitalized)
            }
        }
        InspectorSection(title: "Evidence") {
            ForEach(relationship.evidence, id: \.self) { item in
                VStack(alignment: .leading, spacing: 2) {
                    HStack {
                        Text(item.signal.humanizedKey).font(.callout.weight(.medium))
                        Spacer()
                        Text("+\(item.weight, format: .number.precision(.fractionLength(2)))").font(.caption.monospacedDigit()).foregroundStyle(.spectreSecondary)
                    }
                    Text(item.description).font(.caption)
                    if let urlString = item.sourceUrl, let url = URL(string: urlString) {
                        Link(urlString, destination: url).font(.caption2).lineLimit(1)
                    }
                }
            }
            Text("Weights combine as 1 - product(1 - w). Strong Evidence also requires an explicit link.").font(.caption2).foregroundStyle(.spectreSecondary)
        }
    }
}

private struct IdentityInspector: View {
    let identity: Identity

    var body: some View {
        InspectorSection(title: LocalizedStringKey(identity.kind.label)) {
            Label(identity.label, systemImage: identity.kind.symbol).font(.title3.weight(.semibold))
            KeyValueRow(label: "Value", value: identity.value)
            if let platform = identity.platform { KeyValueRow(label: "Platform", value: platform) }
            if identity.isTarget { TagChip(text: "Investigation target", tint: Theme.accent, symbol: "scope") }
            if identity.verified { TagChip(text: "Ownership verified", tint: Theme.success, symbol: "checkmark.shield") }
            if identity.findingId == nil, !identity.isTarget {
                Text("Known only because another profile links to it; Spectre did not query this account.").font(.caption).foregroundStyle(.spectreSecondary)
            }
        }
    }
}

#Preview("Inspector: finding") {
    InspectorView(item: .finding(PreviewData.findings[0]))
        .environment(AppModel(engine: PreviewEngine()))
        .frame(width: 340, height: 800)
}

#Preview("Inspector: relationship") {
    let graph = PreviewData.graph
    InspectorView(item: .relationship(graph.edges[0], source: graph.nodes[0], target: graph.nodes[1]))
        .environment(AppModel(engine: PreviewEngine()))
        .frame(width: 340, height: 500)
}

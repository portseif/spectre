import SwiftUI

/// One row in the findings list.
struct FindingRow: View {
    let title: String
    let summary: String?
    let kind: FindingKind
    let category: ConfidenceCategory
    let providerName: String
    let isInferred: Bool

    init(finding: Finding) {
        title = finding.title
        summary = finding.summary
        kind = finding.kind
        category = finding.confidence.category
        providerName = finding.sources.first?.providerName ?? finding.providerId
        isInferred = finding.isInferredAssociation
    }

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: kind.symbol)
                .font(.title3)
                .foregroundStyle(Theme.color(for: category))
                .frame(width: 26)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.body.weight(.medium)).lineLimit(1)
                if let summary {
                    Text(summary).font(.callout).foregroundStyle(.spectreSecondary).lineLimit(2)
                }
                HStack(spacing: 6) {
                    Text(providerName)
                    Text("·")
                    Text(isInferred ? "Inferred association" : "Observed fact")
                }
                .font(.caption)
                .foregroundStyle(.spectreSecondary)
            }
            Spacer(minLength: 8)
            ConfidenceBadge(category: category)
        }
        .padding(.vertical, 4)
        .contentShape(.rect)
        .accessibilityElement(children: .combine)
    }
}

/// Kind-specific details for a finding (used by the inspector).
struct FindingDetailContent: View {
    let data: FindingData

    var body: some View {
        switch data {
        case .profile(let profile): ProfileDetail(profile: profile)
        case .emailAssociation(let association): EmailAssociationDetail(association: association)
        case .emailIntelligence(let intelligence): EmailIntelligenceDetail(intelligence: intelligence)
        case .phoneMetadata(let phone): PhoneDetail(phone: phone)
        case .dnsRecords(let dns): DnsDetail(dns: dns)
        case .domainRegistration(let registration): RegistrationDetail(registration: registration)
        case .webPresence(let web): WebPresenceDetail(web: web)
        case .breachIncident(let breach): BreachIncidentDetail(incident: breach.incident, exposedAccount: breach.exposedAccount)
        }
    }
}

private struct ProfileDetail: View {
    let profile: ProfileFinding

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                AsyncImage(url: profile.avatarUrl.flatMap(URL.init(string:))) { image in
                    image.resizable().scaledToFill()
                } placeholder: {
                    Image(systemName: "person.crop.circle.fill").resizable().foregroundStyle(.spectreSecondary)
                }
                .frame(width: 44, height: 44)
                .clipShape(.circle)
                .accessibilityHidden(true)
                VStack(alignment: .leading) {
                    Text(profile.displayName ?? profile.username).font(.headline)
                    Text("\(profile.platform) · @\(profile.username)").font(.caption).foregroundStyle(.spectreSecondary)
                }
                if profile.platformVerified {
                    TagChip(text: "Platform verified", tint: Theme.success, symbol: "checkmark.seal")
                }
            }
            if let bio = profile.bio { Text(bio).font(.callout) }
            if let url = URL(string: profile.profileUrl) {
                Link(destination: url) { Label("Open profile", systemImage: "arrow.up.right.square") }.font(.callout)
            }
            Group {
                if let location = profile.location { KeyValueRow(label: "Location", value: location) }
                if let website = profile.website { KeyValueRow(label: "Website", value: website) }
                if let created = profile.accountCreatedAt { KeyValueRow(label: "Account created", value: created) }
                if let email = profile.publicEmail { KeyValueRow(label: "Public email", value: email) }
                ForEach(profile.attributes.sorted { $0.key < $1.key }, id: \.key) { entry in
                    LabeledContent(entry.key.humanizedKey, value: entry.value).font(.callout)
                }
            }
            if !profile.linkedAccounts.isEmpty {
                Text("Linked accounts").font(.subheadline.weight(.semibold)).padding(.top, 4)
                ForEach(profile.linkedAccounts, id: \.self) { account in
                    LinkedAccountRow(account: account)
                }
            }
        }
    }
}

private struct LinkedAccountRow: View {
    let account: LinkedAccount

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: account.verifiedByPlatform ? "checkmark.seal.fill" : "link")
                .foregroundStyle(account.verifiedByPlatform ? Theme.success : Theme.secondaryText)
                .accessibilityLabel(account.verifiedByPlatform ? Text("Verified by platform") : Text("Unverified link"))
            VStack(alignment: .leading, spacing: 2) {
                if let urlString = account.url, let url = URL(string: urlString) {
                    Link(urlString, destination: url).font(.callout).lineLimit(1)
                } else if let handle = account.handle {
                    Text("@\(handle)").font(.callout)
                }
                if let note = account.note ?? account.platform {
                    Text(note).font(.caption).foregroundStyle(.spectreSecondary)
                }
            }
        }
    }
}

private struct EmailAssociationDetail: View {
    let association: EmailAssociationFinding

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            KeyValueRow(label: "Email", value: association.email)
            KeyValueRow(label: "Discovery method", value: association.discoveryMethod.label)
            HStack { Text("Verification").font(.callout); Spacer(); VerificationBadge(status: association.verificationStatus) }
            Text(association.sourceDescription).font(.caption).foregroundStyle(.spectreSecondary)
            Text("A published address is not proof that the profile owner controls the mailbox. Verify ownership before any account-specific lookup.")
                .font(.caption)
                .foregroundStyle(.spectreSecondary)
        }
    }
}

private struct EmailIntelligenceDetail: View {
    let intelligence: EmailIntelligenceFinding

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            KeyValueRow(label: "Domain", value: intelligence.domain)
            KeyValueRow(label: "Domain exists", value: intelligence.domainResolves ? "Yes" : "No")
            KeyValueRow(label: "Accepts mail", value: intelligence.acceptsMail ? "Yes" : "No")
            if intelligence.nullMx { KeyValueRow(label: "Null MX", value: "Domain accepts no mail (RFC 7505)") }
            ForEach(intelligence.mxRecords, id: \.self) { record in
                KeyValueRow(label: "MX \(record.preference)", value: record.exchange)
            }
            KeyValueRow(label: "SPF", value: intelligence.spf ?? "Not published")
            KeyValueRow(label: "DMARC", value: intelligence.dmarc ?? "Not published")
        }
    }
}

private struct PhoneDetail: View {
    let phone: PhoneNumberInfo

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            KeyValueRow(label: "E.164", value: phone.e164)
            KeyValueRow(label: "International", value: phone.internationalFormat)
            KeyValueRow(label: "National", value: phone.nationalFormat)
            KeyValueRow(label: "Country code", value: "+\(phone.countryCallingCode)")
            KeyValueRow(label: "Region", value: phone.regionCode.map { Locale.current.localizedString(forRegionCode: $0) ?? $0 } ?? "Non-geographic")
            KeyValueRow(label: "Number type", value: phone.numberType.humanizedKey)
            Text("Numbering-plan metadata describes the number range, not the subscriber. Spectre does not infer location or identity from phone numbers.")
                .font(.caption)
                .foregroundStyle(.spectreSecondary)
        }
    }
}

private struct DnsDetail: View {
    let dns: DnsRecordsFinding

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            ForEach(dns.observations, id: \.self) { observation in
                Label(observation, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(Theme.warning)
            }
            ForEach(dns.records, id: \.self) { record in
                HStack(alignment: .top) {
                    Text(record.recordType).font(.caption.monospaced().weight(.semibold)).frame(width: 52, alignment: .leading)
                    Text(record.value).font(.caption.monospaced()).textSelection(.enabled)
                }
            }
        }
    }
}

private struct RegistrationDetail: View {
    let registration: DomainRegistrationFinding

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            KeyValueRow(label: "Registrar", value: registration.registrar ?? "Not disclosed")
            if let date = registration.registeredAt { KeyValueRow(label: "Registered", value: date) }
            if let date = registration.expiresAt { KeyValueRow(label: "Expires", value: date) }
            if let date = registration.lastChangedAt { KeyValueRow(label: "Last changed", value: date) }
            if let signed = registration.dnssecSigned { KeyValueRow(label: "DNSSEC", value: signed ? "Signed" : "Not signed") }
            if !registration.nameservers.isEmpty { KeyValueRow(label: "Nameservers", value: registration.nameservers.joined(separator: "\n")) }
            FlowLayout { ForEach(registration.statuses, id: \.self) { TagChip(text: $0) } }
        }
    }
}

private struct WebPresenceDetail: View {
    let web: WebPresenceFinding

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let title = web.title { KeyValueRow(label: "Title", value: title) }
            if let description = web.description { Text(description).font(.callout) }
            KeyValueRow(label: "HTTP status", value: String(web.statusCode))
            if !web.relMeLinks.isEmpty {
                Text("rel=\"me\" identity links").font(.subheadline.weight(.semibold))
                ForEach(web.relMeLinks, id: \.self) { link in
                    if let url = URL(string: link) { Link(link, destination: url).font(.callout).lineLimit(1) }
                }
            }
            if !web.profileLinks.isEmpty {
                Text("Profile links").font(.subheadline.weight(.semibold))
                ForEach(web.profileLinks, id: \.self) { link in
                    if let url = URL(string: link) { Link(link, destination: url).font(.callout).lineLimit(1) }
                }
            }
            if let security = web.securityTxt {
                Text("security.txt").font(.subheadline.weight(.semibold))
                ForEach(security.contacts, id: \.self) { KeyValueRow(label: "Contact", value: $0) }
                if let expires = security.expires { KeyValueRow(label: "Expires", value: expires) }
            }
        }
    }
}

struct BreachIncidentDetail: View {
    let incident: BreachIncident
    var exposedAccount: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let exposedAccount { KeyValueRow(label: "Exposed account", value: exposedAccount) }
            KeyValueRow(label: "Breach date", value: incident.breachDate ?? "Unknown")
            KeyValueRow(label: "Accounts", value: incident.pwnCount.formatted())
            if let domain = incident.domain { KeyValueRow(label: "Service", value: domain) }
            FlowLayout {
                ForEach(incident.dataClasses, id: \.self) { dataClass in
                    TagChip(text: dataClass, tint: dataClass.lowercased().contains("password") ? Theme.danger : Theme.secondaryText)
                }
            }
            if incident.passwordDataExposed {
                Label("Password data was part of this breach (often hashed). This does not prove that a current password is compromised.", systemImage: "key.slash")
                    .font(.caption)
                    .foregroundStyle(Theme.warning)
            }
            HStack(spacing: 6) {
                if incident.isVerified { TagChip(text: "Verified breach", tint: Theme.success) }
                if !incident.isVerified { TagChip(text: "Unverified breach", tint: Theme.warning) }
                if incident.isSensitive { TagChip(text: "Sensitive", tint: Theme.danger) }
                if incident.isStealerLog { TagChip(text: "Stealer log", tint: Theme.danger) }
                if incident.isSpamList { TagChip(text: "Spam list") }
            }
            Text(incident.description).font(.callout).foregroundStyle(.spectreSecondary)
            Text("Source: \(incident.source)").font(.caption2).foregroundStyle(.spectreSecondary)
        }
    }
}

#Preview("Finding row") {
    List(PreviewData.findings) { FindingRow(finding: $0) }
        .frame(width: 520, height: 320)
}

#Preview("Finding detail") {
    ScrollView {
        VStack(alignment: .leading, spacing: 20) {
            FindingDetailContent(data: PreviewData.findings[0].data)
            Divider()
            FindingDetailContent(data: PreviewData.dnsFinding.data)
            Divider()
            BreachIncidentDetail(incident: PreviewData.breach, exposedAccount: "owner@example.org")
        }
        .padding()
    }
    .frame(width: 340, height: 700)
}

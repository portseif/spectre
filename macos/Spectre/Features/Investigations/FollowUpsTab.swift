import SwiftUI

/// Identifiers the findings point to, plus manual web searches. Spectre never
/// starts these on its own: each one becomes a new investigation with its
/// own authorization record.
struct FollowUpsTab: View {
    @Environment(AppModel.self) private var model
    let investigationID: UUID
    let target: InvestigationTarget?
    let isRunning: Bool
    @State private var followUps: [FollowUp] = []
    @State private var errorMessage: String?

    var body: some View {
        List {
            Section {
                if followUps.isEmpty {
                    Text(isRunning ? "Suggestions appear when the investigation finishes." : "Nothing in the findings points to another identifier.")
                        .foregroundStyle(.spectreSecondary)
                }
                ForEach(followUps) { followUp in
                    FollowUpRow(targetType: followUp.targetType, value: followUp.value, reason: followUp.reason, alreadyInvestigated: followUp.alreadyInvestigated) {
                        model.prepareInvestigation(type: followUp.targetType, value: followUp.value)
                    }
                }
            } header: {
                Text("Suggested follow-ups")
            } footer: {
                Text("Linked handles, published addresses, and websites from this investigation. Starting one asks for its own authorization record.")
            }
            if let errorMessage {
                Label(errorMessage, systemImage: "exclamationmark.triangle.fill").foregroundStyle(Theme.danger)
            }
            if let target {
                Section {
                    ForEach(ManualSearch.links(for: target)) { link in
                        Link(destination: link.url) {
                            Label(link.title, systemImage: "magnifyingglass")
                        }
                    }
                } header: {
                    Text("Search manually")
                } footer: {
                    Text("Opens your browser. Spectre doesn't scrape search engines; these are ordinary searches you run yourself.")
                }
            }
        }
        .listStyle(.inset)
        .task(id: isRunning) { await load() }
    }

    private func load() async {
        guard let engine = model.engine, !isRunning else { return }
        do {
            followUps = try await engine.followUps(investigationID)
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

private struct FollowUpRow: View {
    let targetType: TargetType
    let value: String
    let reason: String
    let alreadyInvestigated: Bool
    let onInvestigate: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: targetType.symbol)
                .frame(width: 24)
                .foregroundStyle(Theme.accent)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(value).font(.body.weight(.medium)).textSelection(.enabled)
                Text(reason).font(.caption).foregroundStyle(.spectreSecondary)
            }
            Spacer()
            if alreadyInvestigated {
                TagChip(text: "Already investigated", tint: Theme.secondaryText)
            }
            Button("Investigate…", action: onInvestigate)
        }
        .accessibilityElement(children: .combine)
    }
}

/// Plain search-engine queries for a target, opened in the user's browser.
enum ManualSearch {
    struct SearchLink: Identifiable {
        let title: String
        let url: URL
        var id: String { url.absoluteString }
    }

    static func links(for target: InvestigationTarget) -> [SearchLink] {
        let value = target.value
        let quoted = "\"\(value)\""
        var queries: [(String, String)] = [("Exact phrase", quoted)]
        switch target.type {
        case .username:
            queries.append(("Social sites without public APIs", "\(quoted) (site:reddit.com OR site:x.com OR site:instagram.com OR site:tiktok.com OR site:threads.net)"))
        case .email:
            if let domain = value.split(separator: "@").last {
                queries.append(("Other addresses on the domain", "\"@\(domain)\" -\(quoted)"))
            }
        case .phone:
            queries.append(("Without the plus sign", "\"\(value.dropFirst())\""))
        case .domain:
            queries.append(("Pages on the site", "site:\(value)"))
            queries.append(("Mentions elsewhere", "\(quoted) -site:\(value)"))
        }
        var links: [SearchLink] = []
        for (title, query) in queries {
            let encoded = query.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed.subtracting(CharacterSet(charactersIn: "&+=#"))) ?? query
            if let duckDuckGo = URL(string: "https://duckduckgo.com/?q=\(encoded)") {
                links.append(SearchLink(title: "\(title) (DuckDuckGo)", url: duckDuckGo))
            }
            if let google = URL(string: "https://www.google.com/search?q=\(encoded)") {
                links.append(SearchLink(title: "\(title) (Google)", url: google))
            }
        }
        return links
    }
}

#Preview {
    FollowUpsTab(investigationID: PreviewData.investigationID, target: PreviewData.investigation.target, isRunning: false)
        .environment(AppModel(engine: PreviewEngine()))
        .frame(width: 700, height: 500)
}

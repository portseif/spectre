import Charts
import SwiftUI

struct DashboardView: View {
    @Environment(AppModel.self) private var model
    @State private var stats: DashboardStats?
    @State private var errorMessage: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Theme.spacing) {
                DashboardHeader()
                if let stats {
                    MetricGrid(stats: stats)
                    // Two charts per row when there is room, one when the window is narrow.
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 340), spacing: Theme.spacing, alignment: .top)], alignment: .leading, spacing: Theme.spacing) {
                        ActivityChart(days: stats.investigationsByDay)
                        ConfidenceChart(categories: stats.findingsByCategory)
                        ProviderChart(providers: stats.findingsByProvider)
                        ExposureChart(years: stats.exposuresByYear)
                    }
                } else if let errorMessage {
                    ContentUnavailableView("Dashboard unavailable", systemImage: "exclamationmark.triangle", description: Text(errorMessage))
                } else {
                    ProgressView().frame(maxWidth: .infinity, minHeight: 200)
                }
                RecentInvestigations(investigations: Array(model.investigations.prefix(6)))
            }
            .padding(24)
            .frame(maxWidth: 1400)
            .frame(maxWidth: .infinity)
        }
        .navigationTitle("Dashboard")
        .task(id: model.investigations) { await load() }
    }

    private func load() async {
        guard let engine = model.engine else { return }
        do {
            stats = try await engine.dashboard()
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

private struct DashboardHeader: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        // Keep the button beside the title when it fits, otherwise move it underneath.
        ViewThatFits(in: .horizontal) {
            HStack(alignment: .firstTextBaseline, spacing: Theme.spacing) {
                DashboardTitle()
                Spacer(minLength: 0)
                NewInvestigationButton { model.selection = .newInvestigation }
            }
            VStack(alignment: .leading, spacing: 12) {
                DashboardTitle()
                NewInvestigationButton { model.selection = .newInvestigation }
            }
        }
    }
}

private struct DashboardTitle: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Intelligence overview").font(.largeTitle.weight(.semibold))
            Text("Public discovery, evidence-based correlation, and authorized breach exposure.")
                .foregroundStyle(.spectreSecondary)
        }
    }
}

private struct NewInvestigationButton: View {
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Label("New Investigation", systemImage: "plus.magnifyingglass")
        }
        .buttonStyle(.borderedProminent)
        .tint(Theme.accent)
        .controlSize(.large)
    }
}

private struct MetricGrid: View {
    let stats: DashboardStats

    var body: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 150), spacing: Theme.spacing)], spacing: Theme.spacing) {
            MetricTile(title: "Investigations", value: stats.investigations.formatted(), symbol: "list.bullet.rectangle")
            MetricTile(title: "Running", value: stats.running.formatted(), symbol: "bolt.horizontal.circle", tint: Theme.secondaryAccent)
            MetricTile(title: "Findings", value: stats.findings.formatted(), symbol: "sparkle.magnifyingglass")
            MetricTile(title: "Public profiles", value: stats.profiles.formatted(), symbol: "person.crop.circle")
            MetricTile(title: "Confirmed links", value: stats.confirmedRelationships.formatted(), symbol: "checkmark.seal", tint: Theme.success)
            MetricTile(title: "Strong evidence", value: stats.strongRelationships.formatted(), symbol: "link", tint: Theme.secondaryAccent)
            MetricTile(title: "Verified emails", value: stats.verifiedEmails.formatted(), symbol: "envelope.badge.shield.half.filled", tint: Theme.success)
            MetricTile(title: "Breach exposures", value: stats.breachExposures.formatted(), symbol: "exclamationmark.shield", tint: Theme.danger)
        }
    }
}

private struct ActivityChart: View {
    let days: [CountByLabel]

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                SectionHeader(title: "Investigations · last 30 days", symbol: "chart.bar")
                if days.isEmpty {
                    Text("No recent investigations").foregroundStyle(.spectreSecondary).frame(maxWidth: .infinity, minHeight: 160)
                } else {
                    Chart(days) { day in
                        BarMark(x: .value("Day", EngineDate.day(from: day.label) ?? .now, unit: .day), y: .value("Investigations", day.count))
                            .foregroundStyle(Theme.accent.gradient)
                    }
                    .chartXAxis {
                        AxisMarks(values: .stride(by: .day)) { _ in
                            AxisGridLine()
                            AxisValueLabel(format: .dateTime.month(.abbreviated).day())
                        }
                    }
                    .frame(height: 160)
                }
            }
        }
    }
}

private struct ConfidenceChart: View {
    let categories: [CountByLabel]

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                SectionHeader(title: "Findings by confidence", symbol: "chart.pie")
                if categories.isEmpty {
                    Text("No findings yet").foregroundStyle(.spectreSecondary).frame(maxWidth: .infinity, minHeight: 160)
                } else {
                    Chart(categories) { entry in
                        let category = ConfidenceCategory(rawValue: entry.label) ?? .unrelated
                        SectorMark(angle: .value("Findings", entry.count), innerRadius: .ratio(0.6), angularInset: 1.5)
                            .foregroundStyle(Theme.color(for: category))
                            .accessibilityLabel(category.label)
                            .accessibilityValue("\(entry.count)")
                    }
                    .frame(height: 160)
                    FlowLayout {
                        ForEach(categories) { entry in
                            let category = ConfidenceCategory(rawValue: entry.label) ?? .unrelated
                            TagChip(text: "\(category.label) · \(entry.count)", tint: Theme.color(for: category))
                        }
                    }
                }
            }
        }
    }
}

private struct ProviderChart: View {
    let providers: [CountByLabel]

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                SectionHeader(title: "Findings by provider", symbol: "server.rack")
                if providers.isEmpty {
                    Text("No findings yet").foregroundStyle(.spectreSecondary).frame(maxWidth: .infinity, minHeight: 160)
                } else {
                    Chart(providers) { provider in
                        BarMark(x: .value("Findings", provider.count), y: .value("Provider", provider.label))
                            .foregroundStyle(Theme.secondaryAccent.gradient)
                    }
                    .frame(height: max(160, CGFloat(providers.count) * 22))
                }
            }
        }
    }
}

private struct ExposureChart: View {
    let years: [CountByLabel]

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                SectionHeader(title: "Breach exposure timeline", symbol: "calendar.badge.exclamationmark")
                if years.isEmpty {
                    Text("No exposures recorded for verified addresses").foregroundStyle(.spectreSecondary).frame(maxWidth: .infinity, minHeight: 160)
                } else {
                    Chart(years) { year in
                        LineMark(x: .value("Year", year.label), y: .value("Exposures", year.count))
                            .foregroundStyle(Theme.danger)
                        PointMark(x: .value("Year", year.label), y: .value("Exposures", year.count))
                            .foregroundStyle(Theme.danger)
                    }
                    .frame(height: 160)
                }
            }
        }
    }
}

private struct RecentInvestigations: View {
    @Environment(AppModel.self) private var model
    let investigations: [Investigation]

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                SectionHeader(title: "Recent investigations", symbol: "clock.arrow.circlepath", count: investigations.count)
                if investigations.isEmpty {
                    Text("Start an investigation to see results here.").foregroundStyle(.spectreSecondary)
                }
                ForEach(investigations) { investigation in
                    Button {
                        model.open(investigation.id)
                    } label: {
                        InvestigationSummaryRow(
                            target: investigation.target.value,
                            targetType: investigation.targetType,
                            status: investigation.status,
                            findings: investigation.findingsCount,
                            createdAt: investigation.createdAt
                        )
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }
}

struct InvestigationSummaryRow: View {
    let target: String
    let targetType: TargetType
    let status: InvestigationStatus
    let findings: UInt32
    let createdAt: Date

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: targetType.symbol)
                .frame(width: 28, height: 28)
                .background(Theme.elevated, in: .rect(cornerRadius: 6))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(target).font(.body.weight(.medium)).lineLimit(1)
                Text("\(targetType.label) · \(createdAt.formatted(.relative(presentation: .named)))")
                    .font(.caption)
                    .foregroundStyle(.spectreSecondary)
            }
            Spacer(minLength: 8)
            Text("\(findings) findings").font(.caption.monospacedDigit()).foregroundStyle(.spectreSecondary).lineLimit(1)
            StatusBadge(status: status)
        }
        .contentShape(.rect)
        .accessibilityElement(children: .combine)
    }
}

#Preview {
    NavigationStack {
        DashboardView()
    }
    .environment(AppModel(engine: PreviewEngine()))
    .frame(width: 980, height: 900)
}

import PDFKit
import SwiftUI
import UniformTypeIdentifiers

struct ReportsView: View {
    @Environment(AppModel.self) private var model
    @State private var investigationID: UUID?
    @State private var pdfData: Data?
    @State private var isGenerating = false
    @State private var exportDocument: ExportDocument?
    @State private var isImporting = false
    @State private var message: String?

    private var completed: [Investigation] {
        model.investigations.filter { $0.status.isTerminal }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Picker("Investigation", selection: $investigationID) {
                    Text("Choose investigation").tag(UUID?.none)
                    ForEach(completed) { investigation in
                        Text("\(investigation.target.value) · \(investigation.createdAt.formatted(date: .abbreviated, time: .shortened))").tag(UUID?.some(investigation.id))
                    }
                }
                .frame(minWidth: 160, maxWidth: 380)
                Spacer(minLength: 8)
                Menu {
                    Button { export(.pdf) } label: { Label("PDF Report", systemImage: "doc.richtext") }
                    Button { export(.json) } label: { Label("JSON Bundle", systemImage: "curlybraces") }
                    Button { export(.csv) } label: { Label("CSV Findings", systemImage: "tablecells") }
                } label: {
                    Label("Export", systemImage: "square.and.arrow.up")
                } primaryAction: {
                    export(.pdf)
                }
                .menuStyle(.button)
                .fixedSize()
                .help("Export the PDF report, or choose JSON or CSV from the menu")
                .disabled(investigationID == nil)
                Button { isImporting = true } label: { Label("Import…", systemImage: "square.and.arrow.down") }
                    .fixedSize()
            }
            .disabled(isGenerating)
            .padding(12)
            if let message {
                Text(message).font(.caption).foregroundStyle(.spectreSecondary).padding(.bottom, 6)
            }
            Divider()
            Group {
                if let pdfData {
                    PDFPreview(data: pdfData)
                } else if isGenerating {
                    ProgressView("Generating report…").frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    ContentUnavailableView("No report", systemImage: "doc.richtext", description: Text("Choose a completed investigation to preview its report."))
                }
            }
        }
        .navigationTitle("Reports")
        .task(id: investigationID) { await generatePreview() }
        .onAppear { if investigationID == nil { investigationID = completed.first?.id } }
        .fileExporter(
            isPresented: Binding(get: { exportDocument != nil }, set: { if !$0 { exportDocument = nil } }),
            document: exportDocument,
            contentType: exportDocument?.contentType ?? .pdf,
            defaultFilename: exportDocument?.filename
        ) { result in
            switch result {
            case .success(let url): message = "Saved \(url.lastPathComponent)"
            case .failure(let error): message = error.localizedDescription
            }
            exportDocument = nil
        }
        .fileImporter(isPresented: $isImporting, allowedContentTypes: [.json]) { result in
            Task { await importBundle(result) }
        }
    }

    private enum Format { case pdf, json, csv }

    private func generatePreview() async {
        guard let engine = model.engine, let investigationID else { pdfData = nil; return }
        isGenerating = true
        defer { isGenerating = false }
        do {
            let detail = try await engine.investigation(investigationID)
            pdfData = await Task.detached(priority: .userInitiated) { ReportGenerator.pdf(for: detail) }.value
        } catch {
            message = error.localizedDescription
            pdfData = nil
        }
    }

    private func export(_ format: Format) {
        guard let engine = model.engine, let investigationID,
              let investigation = completed.first(where: { $0.id == investigationID }) else { return }
        let base = "spectre-\(investigation.target.value)-\(investigation.createdAt.formatted(.iso8601.year().month().day()))"
            .replacingOccurrences(of: "/", with: "-")
        Task {
            do {
                switch format {
                case .pdf:
                    guard let pdfData else { return }
                    exportDocument = ExportDocument(data: pdfData, contentType: .pdf, filename: base + ".pdf")
                case .json:
                    exportDocument = ExportDocument(data: try await engine.exportJSON(investigationID), contentType: .json, filename: base + ".json")
                case .csv:
                    exportDocument = ExportDocument(data: Data(try await engine.exportCSV(investigationID).utf8), contentType: .commaSeparatedText, filename: base + ".csv")
                }
            } catch {
                message = error.localizedDescription
            }
        }
    }

    private func importBundle(_ result: Result<URL, any Error>) async {
        guard let engine = model.engine else { return }
        do {
            let url = try result.get()
            let accessing = url.startAccessingSecurityScopedResource()
            defer { if accessing { url.stopAccessingSecurityScopedResource() } }
            let identifier = try await engine.importBundle(try Data(contentsOf: url))
            await model.refreshInvestigations()
            investigationID = identifier
            message = "Imported \(url.lastPathComponent)"
        } catch {
            message = error.localizedDescription
        }
    }
}

/// In-memory file for `fileExporter`.
struct ExportDocument: FileDocument {
    static let readableContentTypes: [UTType] = [.pdf, .json, .commaSeparatedText]

    let data: Data
    let contentType: UTType
    let filename: String

    init(data: Data, contentType: UTType, filename: String) {
        self.data = data
        self.contentType = contentType
        self.filename = filename
    }

    init(configuration: ReadConfiguration) throws {
        data = configuration.file.regularFileContents ?? Data()
        contentType = configuration.contentType
        filename = configuration.file.filename ?? "export"
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}

/// PDFKit preview.
struct PDFPreview: NSViewRepresentable {
    let data: Data

    func makeNSView(context: Context) -> PDFView {
        let view = PDFView()
        view.autoScales = true
        view.displayMode = .singlePageContinuous
        view.backgroundColor = .underPageBackgroundColor
        return view
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    func updateNSView(_ view: PDFView, context: Context) {
        guard context.coordinator.loaded != data else { return }
        context.coordinator.loaded = data
        view.document = PDFDocument(data: data)
    }

    final class Coordinator {
        var loaded: Data?
    }
}

#Preview {
    NavigationStack { ReportsView() }
        .environment(AppModel(engine: PreviewEngine()))
        .frame(width: 900, height: 700)
}

#Preview("PDF") {
    PDFPreview(data: ReportGenerator.pdf(for: PreviewData.detail, generatedAt: PreviewData.now))
        .frame(width: 640, height: 800)
}

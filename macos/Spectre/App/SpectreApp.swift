import SwiftUI

@main
struct SpectreApp: App {
    @State private var model = AppModel()

    var body: some Scene {
        WindowGroup("Spectre", id: "main") {
            RootView()
                .environment(model)
                .task { await model.bootstrap() }
                .frame(minWidth: 1240, minHeight: 720)
        }
        .defaultSize(width: 1440, height: 900)
        .windowToolbarStyle(.unified)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("New Investigation") { model.selection = .newInvestigation }
                    .keyboardShortcut("n")
            }
            CommandGroup(after: .sidebar) {
                Button(model.isInspectorPresented ? "Hide Inspector" : "Show Inspector") { model.isInspectorPresented.toggle() }
                    .keyboardShortcut("i", modifiers: [.command, .option])
            }
        }

        Settings {
            SettingsView()
                .environment(model)
                .frame(width: 720, height: 540)
        }
    }
}

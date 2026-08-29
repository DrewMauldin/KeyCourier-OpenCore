import AppKit
import SwiftUI

@main
struct KeyCourierApp: App {
    @State private var model: AppModel

    init() {
        let model = AppModel()
        model.startMonitoring()
        _model = State(initialValue: model)
    }

    var body: some Scene {
        WindowGroup("KeyCourier", id: "main") {
            ContentView(model: model)
        }
        .defaultSize(width: 920, height: 620)
        .windowResizability(.contentMinSize)

        MenuBarExtra("KeyCourier", systemImage: "key.viewfinder") {
            MenuBarView(model: model)
        }
        .menuBarExtraStyle(.window)
    }
}

private struct MenuBarView: View {
    @Environment(\.openWindow) private var openWindow
    let model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("KeyCourier").font(.headline)
            Text(model.requests.isEmpty ? "No pending requests" : "\(model.requests.count) pending request(s)")
                .foregroundStyle(.secondary)
            Button("Open KeyCourier") {
                NSApplication.shared.activate(ignoringOtherApps: true)
                openWindow(id: "main")
            }
            Button("Refresh") {
                Task {
                    await model.refresh()
                    model.queueSecretPromptIfNeeded()
                }
            }
        }
        .padding()
        .frame(width: 240)
        .onChange(of: model.pendingSecretPrompt?.id, initial: true) { _, _ in
            guard model.pendingSecretPrompt != nil else { return }
            NSApplication.shared.activate(ignoringOtherApps: true)
            openWindow(id: "main")
        }
    }
}

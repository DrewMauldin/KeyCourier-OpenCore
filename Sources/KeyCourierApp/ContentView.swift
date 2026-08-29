import AppKit
import KeyCourierCore
import SwiftUI

struct ContentView: View {
    enum Sheet: Identifiable {
        case save(GuidedDestination)
        case requestedSecret(SecretRequest)
        case quickCredential
        case customSecret
        case editSecret(SecretMetadata)
        case importDotenv
        case customDestination

        var id: String {
            switch self {
            case .save(let destination): "save-\(destination.rawValue)"
            case .requestedSecret(let request): "requested-secret-\(request.id.uuidString)"
            case .quickCredential: "quick-credential"
            case .customSecret: "custom-secret"
            case .editSecret(let secret): "edit-secret-\(secret.id.rawValue)"
            case .importDotenv: "import-dotenv"
            case .customDestination: "custom-destination"
            }
        }
    }

    @Bindable var model: AppModel
    @State private var presentedSheet: Sheet?

    var body: some View {
        NavigationSplitView {
            List(SidebarSection.allCases, selection: $model.selection) { section in
                Label(section.rawValue, systemImage: section.systemImage)
                    .tag(section)
                    .badge(section == .requests ? model.requests.count : 0)
            }
            .navigationTitle("KeyCourier")
            .navigationSplitViewColumnWidth(min: 170, ideal: 190)
        } detail: {
            detailView
                .toolbar {
                    ToolbarItem {
                        if model.isWorking {
                            ProgressView()
                                .controlSize(.small)
                                .accessibilityLabel("KeyCourier is working")
                        }
                    }
                    ToolbarItem {
                        Button("Refresh", systemImage: "arrow.clockwise", action: refresh)
                    }
                }
        }
        .frame(minWidth: 760, minHeight: 520)
        .task {
            model.startMonitoring()
            await model.refresh()
            model.queueSecretPromptIfNeeded()
            presentPendingSecretPrompt()
        }
        .onChange(of: model.pendingSecretPrompt?.id, initial: true) { _, _ in
            presentPendingSecretPrompt()
        }
        .onChange(of: presentedSheet?.id) { _, _ in
            presentPendingSecretPrompt()
        }
        .sheet(item: $presentedSheet) { sheet in
            switch sheet {
            case .save(let destination):
                GuidedSecretEntryView(model: model, destination: destination)
            case .requestedSecret(let request):
                RequestedSecretEntryView(model: model, request: request)
            case .quickCredential:
                QuickCredentialEntryView(model: model)
            case .customSecret:
                CustomSecretView(model: model)
            case .editSecret(let secret):
                CredentialEditView(model: model, secret: secret)
            case .importDotenv:
                DotenvImportView(model: model)
            case .customDestination:
                CustomDestinationView(model: model)
            }
        }
        .alert("KeyCourier could not complete that action", isPresented: errorBinding) {
            Button("OK", role: .cancel) { model.errorMessage = nil }
        } message: {
            Text(model.errorMessage ?? "Unknown error")
        }
    }

    @ViewBuilder
    private var detailView: some View {
        switch model.selection {
        case .home:
            HomeView(
                model: model,
                addCredential: { presentedSheet = .quickCredential },
                manageCredentials: { model.selection = .credentials },
                copyAgentSetupPrompt: copyAgentSetupPrompt
            )
        case .requests:
            RequestsView(
                model: model,
                pasteSecret: { request in
                    model.markRequestPrompted(request)
                    model.selection = .requests
                    NSApplication.shared.activate(ignoringOtherApps: true)
                    presentedSheet = .requestedSecret(request)
                }
            )
        case .credentials:
            CredentialsView(
                model: model,
                addCredential: { presentedSheet = .quickCredential },
                importCredentials: { presentedSheet = .importDotenv },
                editCredential: { presentedSheet = .editSecret($0) }
            )
        case .history:
            HistoryView(model: model)
        case .settings:
            SettingsView(model: model)
        case .advanced:
            AdvancedView(
                model: model,
                addCustomSecret: { presentedSheet = .customSecret },
                addCustomDestination: { presentedSheet = .customDestination }
            )
        }
    }

    private var errorBinding: Binding<Bool> {
        Binding(
            get: { model.errorMessage != nil },
            set: { if !$0 { model.errorMessage = nil } }
        )
    }

    private func refresh() {
        Task {
            await model.refresh()
            model.queueSecretPromptIfNeeded()
            presentPendingSecretPrompt()
        }
    }

    private func presentPendingSecretPrompt() {
        guard presentedSheet == nil,
              let request = model.takePendingSecretPrompt() else { return }
        model.selection = .requests
        NSApplication.shared.activate(ignoringOtherApps: true)
        presentedSheet = .requestedSecret(request)
    }

    private func copyAgentSetupPrompt() {
        let embeddedCLI = Bundle.main.bundleURL
            .appending(path: "Contents/Resources/Automation/keycourier")
            .path(percentEncoded: false)
        let prompt = """
        Complete the KeyCourier AI setup checklist on this Mac. Use the bundled KeyCourier command at `\(embeddedCLI)`. Start with `"\(embeddedCLI)" doctor`, then use only reviewed KeyCourier or host-integration commands to resolve reported setup items. Keep KeyCourier open so its destination checklist can update automatically. You may inspect `"\(embeddedCLI)" secrets` and `"\(embeddedCLI)" consumers`; treat their output as content-free metadata. Never ask me to paste a credential into chat, read Keychain values, inspect .env or secret files, expose Docker environments, bypass owner approval, or approve your own request. When a value is required, ask me to add it in the KeyCourier app. Use content-free connection checks and report the exact evidence for each destination that becomes ready.
        """
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(prompt, forType: .string)
    }
}

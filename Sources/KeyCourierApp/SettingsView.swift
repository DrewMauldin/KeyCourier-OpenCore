import KeyCourierCore
import SwiftUI
import UniformTypeIdentifiers

enum ApprovalPreferenceKey {
    static let companion = "approvalDefaults.companion"
    static let telegram = "approvalDefaults.telegram"
}

struct SettingsView: View {
    let model: AppModel
    @AppStorage(ApprovalPreferenceKey.companion) private var defaultCompanionApproval = false
    @AppStorage(ApprovalPreferenceKey.telegram) private var defaultTelegramApproval = false
    @State private var botToken = ""
    @State private var recoveryRecipients = ""
    @State private var didLoad = false
    @State private var showRecoveryExporter = false
    @State private var showRecoveryImporter = false
    @State private var operationMessage: String?
    @State private var showingCompanionTurnOffConfirmation = false

    var body: some View {
        List {
            Section("Notifications") {
                Label(
                    model.notificationsEnabled ? "Notifications are on" : "Notifications are off",
                    systemImage: model.notificationsEnabled ? "bell.badge.fill" : "bell.slash"
                )
                .foregroundStyle(model.notificationsEnabled ? .green : .secondary)
                if !model.notificationsEnabled {
                    Button("Enable notifications", action: enableNotifications)
                }
                Text("KeyCourier can notify you when an approval is waiting and when delivery finishes. Notifications never contain credential values.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            companionSection
            telegramSection
            recoverySection
            Section("Help and privacy") {
                Link("KeyCourier Support", destination: URL(string: "https://keycourier.drewsdigest.com/support/")!)
                Link("Privacy Policy", destination: URL(string: "https://keycourier.drewsdigest.com/privacy/")!)
                Text("Never include a credential value, private key, environment dump or ciphertext in a support request.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Settings")
        .confirmationDialog(
            "Turn off iPhone companion?",
            isPresented: $showingCompanionTurnOffConfirmation,
            titleVisibility: .visible
        ) {
            Button("Turn Off", role: .destructive) {
                Task { await model.setCompanionEnabled(false) }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This permanently removes pending approvals and encrypted credential additions waiting in iCloud.")
        }
        .task { loadOnce() }
        .fileExporter(
            isPresented: $showRecoveryExporter,
            document: EmptyRecoveryDocument(),
            contentType: .data,
            defaultFilename: "KeyCourier-Recovery.age",
            onCompletion: handleRecoveryExport
        )
        .fileExporterFilenameLabel("Save encrypted backup as")
        .fileImporter(
            isPresented: $showRecoveryImporter,
            allowedContentTypes: [.data, .plainText],
            allowsMultipleSelection: true,
            onCompletion: handleRecoveryImport
        )
        .fileDialogMessage("Select one KeyCourier .age backup and its offline age identity file")
        .fileDialogConfirmationLabel("Restore")
        .alert("KeyCourier", isPresented: operationMessageBinding) {
            Button("OK", role: .cancel) { operationMessage = nil }
        } message: {
            Text(operationMessage ?? "")
        }
    }

    @ViewBuilder
    private var companionSection: some View {
        Section("iPhone companion") {
            if model.companionConfiguration.isEnabled {
                if let trusted = model.companionConfiguration.trustedDevice {
                    Label("Paired with \(trusted.registration.deviceName)", systemImage: "iphone.gen3.radiowaves.left.and.right")
                        .foregroundStyle(.green)
                    Toggle("Allow iPhone approval for new credentials", isOn: $defaultCompanionApproval)
                    Text("Existing credentials are unchanged.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    if let code = model.companionPairingCode {
                        LabeledContent("Pairing code") {
                            Text(code)
                                .font(.system(.body, design: .monospaced))
                                .textSelection(.enabled)
                        }
                        Text("Confirm that this exact code appears on the iPhone before approving requests or sending credentials.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Button("Remove paired iPhone", role: .destructive) {
                        Task { await model.removeTrustedCompanion() }
                    }
                } else {
                    Label("Waiting for an iPhone", systemImage: "iphone")
                        .foregroundStyle(.secondary)
                }

                ForEach(model.companionRegistrations) { registration in
                    VStack(alignment: .leading, spacing: 8) {
                        Text(registration.deviceName)
                            .font(.headline)
                        Text("Confirm that this is your iPhone. Approval pairs its device keys after Mac owner authentication.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        HStack {
                            Button("Decline", role: .destructive) {
                                Task { await model.declineCompanionRegistration(registration) }
                            }
                            Button("Pair iPhone") {
                                Task { await model.approveCompanionRegistration(registration) }
                            }
                            .buttonStyle(.borderedProminent)
                            .disabled(model.companionConfiguration.trustedDevice != nil)
                        }
                    }
                    .padding(.vertical, 4)
                }

                Button("Check companion now", systemImage: "arrow.clockwise") {
                    Task { await model.processCompanion(force: true) }
                }
                Button("Turn off iPhone companion", role: .destructive) {
                    showingCompanionTurnOffConfirmation = true
                }
            } else {
                Button("Enable iPhone companion", systemImage: "iphone.gen3") {
                    Task { await model.setCompanionEnabled(true) }
                }
                .buttonStyle(.borderedProminent)
            }

            Text("The private iCloud database carries request metadata, signed decisions and encrypted credential envelopes. Plaintext values remain inside the owner-authenticated apps and the Mac Keychain.")
                .font(.caption)
                .foregroundStyle(.secondary)
            if let status = model.companionStatusMessage {
                Text(status)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder
    private var telegramSection: some View {
        Section("Telegram approvals") {
            if let configuration = model.telegramConfiguration {
                Label("Connected to @\(configuration.botUsername)", systemImage: "checkmark.shield.fill")
                    .foregroundStyle(.green)
                Toggle("Allow Telegram approval for new credentials", isOn: $defaultTelegramApproval)
                Text("Existing credentials are unchanged.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text("Only the paired private chat and Telegram user can use a single-use approval button. Telegram receives friendly request metadata, never a credential value.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Button("Disconnect Telegram", role: .destructive) {
                    Task { await model.disconnectTelegram() }
                }
                DisclosureGroup("Advanced") {
                    LabeledContent("Chat ID", value: String(configuration.chatID))
                    LabeledContent("User ID", value: String(configuration.userID))
                    Text("Telegram Bot API messages are not end-to-end encrypted. Keep approval titles and destination names non-sensitive.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } else if let code = model.telegramPairingCode,
                      let username = model.telegramBotUsername {
                Text("1. Open @\(username) in Telegram.")
                Text("2. Send this exact message:")
                Text("/pair \(code)")
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                Button("I sent it", action: completeTelegramPairing)
                    .buttonStyle(.borderedProminent)
                Button("Start over", role: .cancel) {
                    Task { await model.disconnectTelegram() }
                }
            } else {
                SecureField("Bot token from BotFather", text: $botToken)
                Button("Connect Telegram", action: startTelegramPairing)
                    .buttonStyle(.borderedProminent)
                    .disabled(botToken.isEmpty || model.isWorking)
                Text("Create a private bot with BotFather, paste its token here, then pair your own private chat using a one-time code.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            if let status = model.telegramStatusMessage {
                Text(status)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder
    private var recoverySection: some View {
        Section("Encrypted recovery") {
            TextEditor(text: $recoveryRecipients)
                .font(.system(.body, design: .monospaced))
                .frame(minHeight: 72)
                .accessibilityLabel("Offline age recipients, one per line")
            Text("Add one or more public age recipients, one per line. Keep each matching private identity offline. Saving a new list and exporting again rekeys the backup.")
                .font(.caption)
                .foregroundStyle(.secondary)
            Button("Save recovery recipients", action: saveRecoveryRecipients)
            HStack {
                Button("Export encrypted backup", systemImage: "lock.doc") {
                    showRecoveryExporter = true
                }
                .disabled(model.recoveryConfiguration == nil || model.secrets.isEmpty)
                Button("Restore encrypted backup", systemImage: "arrow.counterclockwise") {
                    showRecoveryImporter = true
                }
            }

            ForEach(model.remoteRecipientCounts, id: \.name) { summary in
                LabeledContent(summary.name, value: "\(summary.count) encrypted recipients")
            }

            DisclosureGroup("Advanced") {
                Text("Recovery exports contain credential values only inside the age-encrypted payload. The output file is written mode 600. Restoring merges records after validating the whole bundle.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var operationMessageBinding: Binding<Bool> {
        Binding(get: { operationMessage != nil }, set: { if !$0 { operationMessage = nil } })
    }

    private func loadOnce() {
        guard !didLoad else { return }
        didLoad = true
        recoveryRecipients = model.recoveryConfiguration?.ageRecipients.joined(separator: "\n") ?? ""
    }

    private func enableNotifications() {
        Task { await model.enableNotifications() }
    }

    private func startTelegramPairing() {
        let token = botToken
        botToken = ""
        Task { _ = await model.startTelegramPairing(botToken: token) }
    }

    private func completeTelegramPairing() {
        Task { _ = await model.completeTelegramPairing() }
    }

    private func saveRecoveryRecipients() {
        let recipients = recoveryRecipients
            .split(whereSeparator: \Character.isNewline)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        Task {
            if await model.saveRecoveryRecipients(recipients) {
                operationMessage = "Recovery recipients saved. Export a fresh backup to apply them."
            }
        }
    }

    private func handleRecoveryExport(_ result: Result<URL, Error>) {
        guard case .success(let url) = result else {
            if case .failure(let error) = result { operationMessage = error.localizedDescription }
            return
        }
        Task {
            let accessing = url.startAccessingSecurityScopedResource()
            defer { if accessing { url.stopAccessingSecurityScopedResource() } }
            if await model.exportRecoveryBackup(to: url) {
                operationMessage = "Encrypted recovery backup exported."
            } else {
                operationMessage = model.errorMessage
                model.errorMessage = nil
            }
        }
    }

    private func handleRecoveryImport(_ result: Result<[URL], Error>) {
        guard case .success(let urls) = result else {
            if case .failure(let error) = result { operationMessage = error.localizedDescription }
            return
        }
        guard urls.count == 2,
              let backup = urls.first(where: { $0.pathExtension.lowercased() == "age" }),
              let identity = urls.first(where: { $0 != backup }) else {
            operationMessage = "Select exactly one .age backup and one age identity file."
            return
        }
        Task {
            let backupAccess = backup.startAccessingSecurityScopedResource()
            let identityAccess = identity.startAccessingSecurityScopedResource()
            defer {
                if backupAccess { backup.stopAccessingSecurityScopedResource() }
                if identityAccess { identity.stopAccessingSecurityScopedResource() }
            }
            if await model.restoreRecoveryBackup(from: backup, identityURL: identity) {
                operationMessage = "Encrypted recovery backup restored."
            } else {
                operationMessage = model.errorMessage
                model.errorMessage = nil
            }
        }
    }
}

private struct EmptyRecoveryDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }

    init() {}

    init(configuration: ReadConfiguration) throws {}

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: Data())
    }
}

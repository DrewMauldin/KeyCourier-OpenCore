import KeyCourierCore
import SwiftUI
import UniformTypeIdentifiers

struct CustomSecretView: View {
    @Environment(\.dismiss) private var dismiss
    let model: AppModel
    @State private var id = ""
    @State private var generatedSecretID = "credential-\(UUID().uuidString.lowercased())"
    @State private var displayName = ""
    @State private var kind: SecretKind = .apiKey
    @State private var value = ""
    @State private var ownerName = ""
    @State private var projectName = ""
    @State private var environmentName = ""
    @State private var hasRotationDate = false
    @State private var rotationDueAt = Date().addingTimeInterval(90 * 24 * 60 * 60)
    @State private var hasExpiryDate = false
    @State private var expiresAt = Date().addingTimeInterval(365 * 24 * 60 * 60)
    @State private var allowsTelegramApproval = false
    @State private var allowsCompanionApproval = false
    @State private var submissionError: String?

    var body: some View {
        NavigationStack {
            Form {
                TextField("Name (optional)", text: $displayName, prompt: Text("Cloudflare API"))
                Text("Leave this blank to use a generated name.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Picker("Type", selection: $kind) {
                    ForEach(SecretKind.allCases, id: \.self) { secretKind in
                        Text(secretKind.displayName).tag(secretKind)
                    }
                }
                SecureField("Secret value", text: $value)

                Section("Organisation") {
                    TextField("Project", text: $projectName, prompt: Text("Second Brain"))
                    TextField("Environment", text: $environmentName, prompt: Text("Production"))
                    TextField("Owner", text: $ownerName, prompt: Text("Drew"))
                }

                Section("Lifecycle") {
                    Toggle("Track a rotation date", isOn: $hasRotationDate)
                    if hasRotationDate {
                        DatePicker("Rotate by", selection: $rotationDueAt, displayedComponents: .date)
                    }
                    Toggle("This credential expires", isOn: $hasExpiryDate)
                    if hasExpiryDate {
                        DatePicker("Expires", selection: $expiresAt, displayedComponents: .date)
                    }
                }

                Section("Approval") {
                    Toggle("Allow paired iPhone approval", isOn: $allowsCompanionApproval)
                        .disabled(model.companionConfiguration.trustedDevice == nil)
                    Toggle("Allow paired Telegram approval", isOn: $allowsTelegramApproval)
                        .disabled(model.telegramConfiguration == nil)
                    Text(remoteApprovalDescription)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                DisclosureGroup("Advanced") {
                    TextField("Secret ID", text: $id, prompt: Text(suggestedID))
                        .textContentType(.username)
                    Text("Agents use this internal identifier. Leave it blank to use the suggested value.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Text("The value is stored only in this Mac's data-protection Keychain and is cleared from this form immediately.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .formStyle(.grouped)
            .navigationTitle("Add custom credential")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", role: .cancel) { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save", action: submit)
                        .disabled(suggestedID.isEmpty || value.isEmpty || model.isWorking)
                }
            }
        }
        .frame(minWidth: 500, minHeight: 620)
        .alert("Secret was not saved", isPresented: submissionErrorBinding) {
            Button("OK", role: .cancel) { submissionError = nil }
        } message: {
            Text(submissionError ?? "Unknown error")
        }
    }

    private var submissionErrorBinding: Binding<Bool> {
        Binding(get: { submissionError != nil }, set: { if !$0 { submissionError = nil } })
    }

    private func cancel() {
        value = ""
        dismiss()
    }

    private func submit() {
        let secret = Data(value.utf8)
        value = ""
        Task {
            if await model.addSecret(
                id: suggestedID,
                displayName: effectiveDisplayName,
                kind: kind,
                value: secret,
                ownerName: ownerName,
                projectName: projectName,
                environmentName: environmentName,
                rotationDueAt: hasRotationDate ? rotationDueAt : nil,
                expiresAt: hasExpiryDate ? expiresAt : nil,
                allowsTelegramApproval: allowsTelegramApproval,
                allowsCompanionApproval: allowsCompanionApproval
            ) {
                dismiss()
            } else {
                submissionError = model.errorMessage
                model.errorMessage = nil
            }
        }
    }

    private var suggestedID: String {
        let source = id.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? displayName
            : id
        var value = String(source.lowercased().unicodeScalars.map {
            $0.value < 128 && CharacterSet.alphanumerics.contains($0)
                ? Character(String($0))
                : "-"
        })
        value = value
            .split(separator: "-", omittingEmptySubsequences: true)
            .joined(separator: "-")
        if value.count > 64 { value = String(value.prefix(64)) }
        return value.isEmpty ? generatedSecretID : value
    }

    private var effectiveDisplayName: String {
        let value = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else {
            return "Credential \(suggestedID.suffix(6).uppercased())"
        }
        return value
    }

    private var remoteApprovalDescription: String {
        if allowsCompanionApproval && allowsTelegramApproval {
            return "The paired iPhone or Telegram can approve this credential."
        }
        if allowsCompanionApproval {
            return "The paired iPhone can approve this credential after Face ID or device passcode."
        }
        if allowsTelegramApproval {
            return "The paired Telegram chat can approve this credential."
        }
        return "Delivery requires approval on this Mac. Pair remote approval methods in Settings."
    }
}

struct CustomDestinationView: View {
    @Environment(\.dismiss) private var dismiss
    let model: AppModel
    @State private var id = ""
    @State private var displayName = ""
    @State private var path = ""
    @State private var variable = ""
    @State private var submissionError: String?

    var body: some View {
        NavigationStack {
            Form {
                TextField("Name", text: $displayName, prompt: Text("Local project"))
                TextField("Environment file", text: $path, prompt: Text("/Users/me/project/.env"))
                TextField("Variable name", text: $variable, prompt: Text("SERVICE_API_KEY"))
                DisclosureGroup("Advanced") {
                    TextField("Consumer ID", text: $id, prompt: Text(suggestedID))
                    LabeledContent("Target", value: "This Mac")
                }
                Text("KeyCourier changes only this named variable and keeps one protected rollback copy of an existing file.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .formStyle(.grouped)
            .navigationTitle("Add local destination")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", role: .cancel) { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Add", action: submit)
                        .disabled(suggestedID.isEmpty || displayName.isEmpty || path.isEmpty || variable.isEmpty)
                }
            }
        }
        .frame(minWidth: 500, minHeight: 400)
        .alert("Destination was not added", isPresented: submissionErrorBinding) {
            Button("OK", role: .cancel) { submissionError = nil }
        } message: {
            Text(submissionError ?? "Unknown error")
        }
    }

    private var submissionErrorBinding: Binding<Bool> {
        Binding(get: { submissionError != nil }, set: { if !$0 { submissionError = nil } })
    }

    private func submit() {
        Task {
            if await model.addConsumer(
                id: suggestedID,
                displayName: displayName,
                targetID: "this-mac",
                path: path,
                variable: variable
            ) {
                dismiss()
            } else {
                submissionError = model.errorMessage
                model.errorMessage = nil
            }
        }
    }

    private var suggestedID: String {
        let source = id.isEmpty ? displayName : id
        var value = String(source.lowercased().map { $0.isLetter || $0.isNumber ? $0 : "-" })
        value = value
            .split(separator: "-", omittingEmptySubsequences: true)
            .joined(separator: "-")
        if value.count > 64 { value = String(value.prefix(64)) }
        return value
    }
}

struct CredentialEditView: View {
    @Environment(\.dismiss) private var dismiss
    let model: AppModel
    let secret: SecretMetadata

    @State private var didLoad = false
    @State private var mode: CredentialEntryMode = .single
    @State private var displayName = ""
    @State private var ownerName = ""
    @State private var projectName = ""
    @State private var environmentName = ""
    @State private var hasRotationDate = false
    @State private var rotationDueAt = Date()
    @State private var hasExpiryDate = false
    @State private var expiresAt = Date()
    @State private var allowsTelegramApproval = false
    @State private var allowsCompanionApproval = false
    @State private var replacementValue = ""
    @State private var username = ""
    @State private var password = ""
    @State private var submissionError: String?
    @FocusState private var focusedField: Field?

    private enum Field: Hashable {
        case value
        case username
        case password
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Paste the replacement key or password here")
                            .font(.headline)
                        Text(secret.displayName)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }

                    Picker("Format", selection: $mode) {
                        ForEach(CredentialEntryMode.allCases) { mode in
                            Text(mode.title).tag(mode)
                        }
                    }
                    .pickerStyle(.segmented)

                    switch mode {
                    case .single:
                        SecureField("Paste replacement key or password", text: $replacementValue)
                            .textContentType(.password)
                            .focused($focusedField, equals: .value)
                    case .usernamePassword:
                        TextField("Username", text: $username)
                            .textContentType(.username)
                            .focused($focusedField, equals: .username)
                        SecureField("Password", text: $password)
                            .textContentType(.password)
                            .focused($focusedField, equals: .password)
                        Text("KeyCourier stores the pair together and delivers it as compact username/password JSON to the approved destination.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                } footer: {
                    Text("KeyCourier never reveals the saved value. The replacement is written directly to the protected Keychain.")
                }

                DisclosureGroup("Advanced details") {
                    TextField("Name", text: $displayName)
                    Section("Organisation") {
                        TextField("Project", text: $projectName)
                        TextField("Environment", text: $environmentName)
                        TextField("Owner", text: $ownerName)
                    }
                    Section("Lifecycle") {
                        Toggle("Track a rotation date", isOn: $hasRotationDate)
                        if hasRotationDate {
                            DatePicker("Rotate by", selection: $rotationDueAt, displayedComponents: .date)
                        }
                        Toggle("This credential expires", isOn: $hasExpiryDate)
                        if hasExpiryDate {
                            DatePicker("Expires", selection: $expiresAt, displayedComponents: .date)
                        }
                    }
                    Section("Approval") {
                        Toggle("Allow paired iPhone approval", isOn: $allowsCompanionApproval)
                            .disabled(model.companionConfiguration.trustedDevice == nil && !secret.allowsCompanionApproval)
                        Toggle("Allow paired Telegram approval", isOn: $allowsTelegramApproval)
                            .disabled(model.telegramConfiguration == nil && !secret.allowsTelegramApproval)
                        if model.telegramConfiguration == nil && !secret.allowsTelegramApproval {
                            Text("Connect Telegram in Settings before enabling remote approval.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        if allowsTelegramApproval != secret.allowsTelegramApproval
                            || allowsCompanionApproval != secret.allowsCompanionApproval {
                            Text("Changing remote approval access also requires a replacement value so KeyCourier can rewrite the protected Keychain item.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    DisclosureGroup("Identifiers") {
                        LabeledContent("Secret ID", value: secret.id.rawValue)
                        LabeledContent("Type", value: secret.kind.displayName)
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Replace credential")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", role: .cancel, action: cancel)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save", action: submit)
                        .disabled(!canSubmit || model.isWorking)
                }
            }
        }
        .frame(minWidth: 500, minHeight: 320)
        .task { loadOnce() }
        .defaultFocus($focusedField, .value)
        .onChange(of: mode) { _, newMode in
            clearInactiveInput(for: newMode)
            focusedField = newMode == .single ? .value : .username
        }
        .alert("Credential was not updated", isPresented: submissionErrorBinding) {
            Button("OK", role: .cancel) { submissionError = nil }
        } message: {
            Text(submissionError ?? "Unknown error")
        }
    }

    private var canSubmit: Bool {
        switch mode {
        case .single:
            !replacementValue.isEmpty
                || (advancedDetailsChanged && mode.materialKind == secret.materialKind)
        case .usernamePassword:
            !username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !password.isEmpty
        }
    }

    private var submissionErrorBinding: Binding<Bool> {
        Binding(get: { submissionError != nil }, set: { if !$0 { submissionError = nil } })
    }

    private func loadOnce() {
        guard !didLoad else { return }
        didLoad = true
        mode = secret.materialKind == .usernamePassword ? .usernamePassword : .single
        displayName = secret.displayName
        ownerName = secret.ownerName ?? ""
        projectName = secret.projectName ?? ""
        environmentName = secret.environmentName ?? ""
        hasRotationDate = secret.rotationDueAt != nil
        rotationDueAt = secret.rotationDueAt ?? Date().addingTimeInterval(90 * 24 * 60 * 60)
        hasExpiryDate = secret.expiresAt != nil
        expiresAt = secret.expiresAt ?? Date().addingTimeInterval(365 * 24 * 60 * 60)
        allowsTelegramApproval = secret.allowsTelegramApproval
        allowsCompanionApproval = secret.allowsCompanionApproval
    }

    private var advancedDetailsChanged: Bool {
        displayName != secret.displayName
            || ownerName != (secret.ownerName ?? "")
            || projectName != (secret.projectName ?? "")
            || environmentName != (secret.environmentName ?? "")
            || (hasRotationDate ? rotationDueAt : nil) != secret.rotationDueAt
            || (hasExpiryDate ? expiresAt : nil) != secret.expiresAt
            || allowsTelegramApproval != secret.allowsTelegramApproval
            || allowsCompanionApproval != secret.allowsCompanionApproval
    }

    private func submit() {
        let replacement = replacementValue.isEmpty ? nil : Data(replacementValue.utf8)
        let entry: CredentialEntry
        switch mode {
        case .single:
            entry = .single(replacement ?? Data())
        case .usernamePassword:
            entry = .usernamePassword(username: username, password: Data(password.utf8))
        }
        replacementValue = ""
        username = ""
        password = ""
        focusedField = nil
        let updated = SecretMetadata(
            secretID: secret.id,
            displayName: displayName,
            kind: secret.kind,
            materialKind: mode.materialKind,
            createdAt: secret.createdAt,
            updatedAt: Date(),
            ownerName: ownerName,
            projectName: projectName,
            environmentName: environmentName,
            rotationDueAt: hasRotationDate ? rotationDueAt : nil,
            expiresAt: hasExpiryDate ? expiresAt : nil,
            allowsTelegramApproval: allowsTelegramApproval,
            allowsCompanionApproval: allowsCompanionApproval
        )
        Task {
            let didSave: Bool
            switch entry {
            case .single:
                didSave = await model.updateSecretMetadata(updated, replacementValue: replacement)
            case .usernamePassword:
                didSave = await model.replaceCredential(entry, for: updated)
            }
            if didSave {
                dismiss()
            } else {
                submissionError = model.errorMessage
                model.errorMessage = nil
            }
        }
    }

    private func cancel() {
        clearInput()
        dismiss()
    }

    private func clearInactiveInput(for mode: CredentialEntryMode) {
        switch mode {
        case .single:
            username = ""
            password = ""
        case .usernamePassword:
            replacementValue = ""
        }
    }

    private func clearInput() {
        replacementValue = ""
        username = ""
        password = ""
        focusedField = nil
    }
}

struct DotenvImportView: View {
    @Environment(\.dismiss) private var dismiss
    let model: AppModel
    @State private var projectName = ""
    @State private var environmentName = ""
    @State private var showImporter = false
    @State private var submissionError: String?

    var body: some View {
        NavigationStack {
            Form {
                Section("Where these belong") {
                    TextField("Project", text: $projectName, prompt: Text("Second Brain"))
                    TextField("Environment", text: $environmentName, prompt: Text("Production"))
                }
                Section {
                    Button("Choose .env file", systemImage: "doc.badge.plus") {
                        showImporter = true
                    }
                    Text("KeyCourier imports named values directly into Keychain. It does not copy the source path or retain the plaintext file.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Import credentials")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close", role: .cancel) { dismiss() }
                }
            }
        }
        .frame(minWidth: 480, minHeight: 320)
        .fileImporter(
            isPresented: $showImporter,
            allowedContentTypes: [.plainText],
            allowsMultipleSelection: false,
            onCompletion: handleImport
        )
        .fileDialogMessage("Choose an owner-controlled .env file to import")
        .fileDialogConfirmationLabel("Import")
        .alert("Credentials were not imported", isPresented: submissionErrorBinding) {
            Button("OK", role: .cancel) { submissionError = nil }
        } message: {
            Text(submissionError ?? "Unknown error")
        }
    }

    private var submissionErrorBinding: Binding<Bool> {
        Binding(get: { submissionError != nil }, set: { if !$0 { submissionError = nil } })
    }

    private func handleImport(_ result: Result<[URL], Error>) {
        guard case .success(let urls) = result, let url = urls.first else {
            if case .failure(let error) = result { submissionError = error.localizedDescription }
            return
        }
        Task {
            let accessing = url.startAccessingSecurityScopedResource()
            defer { if accessing { url.stopAccessingSecurityScopedResource() } }
            if await model.importDotenv(
                from: url,
                projectName: projectName,
                environmentName: environmentName
            ) {
                dismiss()
            } else {
                submissionError = model.errorMessage
                model.errorMessage = nil
            }
        }
    }
}

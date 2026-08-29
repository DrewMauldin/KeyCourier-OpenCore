import KeyCourierCore
import SwiftUI

struct QuickCredentialEntryView: View {
    @Environment(\.dismiss) private var dismiss
    let model: AppModel

    @State private var mode: CredentialEntryMode = .single
    @State private var displayName = ""
    @State private var value = ""
    @State private var username = ""
    @State private var password = ""
    @State private var submissionError: String?
    @AppStorage(ApprovalPreferenceKey.companion) private var defaultCompanionApproval = false
    @AppStorage(ApprovalPreferenceKey.telegram) private var defaultTelegramApproval = false
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
                    Picker("Format", selection: $mode) {
                        ForEach(CredentialEntryMode.allCases) { mode in
                            Text(mode.title).tag(mode)
                        }
                    }
                    .pickerStyle(.segmented)

                    switch mode {
                    case .single:
                        HStack {
                            SecureField("Paste key or password", text: $value)
                                .textContentType(.password)
                                .autocorrectionDisabled()
                                .focused($focusedField, equals: .value)
                            PasteButton(payloadType: String.self) { strings in
                                value = strings.first ?? ""
                            }
                            .labelStyle(.iconOnly)
                            .help("Paste from the clipboard")
                        }
                    case .usernamePassword:
                        TextField("Username", text: $username)
                            .textContentType(.username)
                            .autocorrectionDisabled()
                            .focused($focusedField, equals: .username)
                        HStack {
                            SecureField("Password", text: $password)
                                .textContentType(.password)
                                .autocorrectionDisabled()
                                .focused($focusedField, equals: .password)
                            PasteButton(payloadType: String.self) { strings in
                                password = strings.first ?? ""
                            }
                            .labelStyle(.iconOnly)
                            .help("Paste password from the clipboard")
                        }
                        Text("KeyCourier stores the pair together and delivers it as compact username/password JSON to the approved destination.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }

                    TextField("Name (optional)", text: $displayName, prompt: Text("Cloudflare API"))
                        .autocorrectionDisabled()
                } header: {
                    Text("Add credential")
                } footer: {
                    Text("The name can appear in approval prompts. The value is stored only in this Mac's protected Keychain and is cleared from this form before saving.")
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Add credential")
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
        .frame(minWidth: 500, minHeight: 300)
        .defaultFocus($focusedField, .value)
        .onChange(of: mode) { _, newMode in
            clearInactiveInput(for: newMode)
            focusedField = newMode == .single ? .value : .username
        }
        .alert("Credential was not saved", isPresented: submissionErrorBinding) {
            Button("OK", role: .cancel) { submissionError = nil }
        } message: {
            Text(submissionError ?? "Unknown error")
        }
    }

    private var canSubmit: Bool {
        switch mode {
        case .single:
            !value.isEmpty
        case .usernamePassword:
            !username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !password.isEmpty
        }
    }

    private var submissionErrorBinding: Binding<Bool> {
        Binding(get: { submissionError != nil }, set: { if !$0 { submissionError = nil } })
    }

    private func resolvedDisplayName(secretID: String) -> String {
        let name = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else {
            let suffix = secretID.suffix(6).uppercased()
            let label = mode == .usernamePassword ? "Username and password" : "Key or password"
            return "\(label) \(suffix)"
        }
        return name
    }

    private var inferredKind: SecretKind {
        if mode == .usernamePassword {
            return .password
        }
        let name = displayName.lowercased()
        if name.contains("password") || name.contains("passwd") {
            return .password
        }
        if name.contains("token") {
            return .token
        }
        return .apiKey
    }

    private func cancel() {
        clearInput()
        dismiss()
    }

    private func submit() {
        let material: CompanionCredentialMaterial
        switch mode {
        case .single:
            material = .single(Data(value.utf8))
        case .usernamePassword:
            material = .usernamePassword(username: username, password: Data(password.utf8))
        }

        let deliveryValue: Data
        do {
            deliveryValue = try material.deliveryData()
        } catch {
            submissionError = error.localizedDescription
            return
        }

        let secretID = uniqueSecretID()
        let displayName = resolvedDisplayName(secretID: secretID)
        let kind = inferredKind
        clearInput()

        Task {
            if await model.addSecret(
                id: secretID,
                displayName: displayName,
                kind: kind,
                value: deliveryValue,
                materialKind: mode.materialKind,
                allowsTelegramApproval: defaultTelegramApproval && model.telegramConfiguration != nil,
                allowsCompanionApproval: defaultCompanionApproval
                    && model.companionConfiguration.trustedDevice != nil
            ) {
                dismiss()
            } else {
                submissionError = model.errorMessage
                model.errorMessage = nil
            }
        }
    }

    private func uniqueSecretID() -> String {
        while true {
            let candidate = "credential-\(UUID().uuidString.lowercased())"
            if !model.secrets.contains(where: { $0.id.rawValue == candidate }) {
                return candidate
            }
        }
    }

    private func clearInactiveInput(for mode: CredentialEntryMode) {
        switch mode {
        case .single:
            username = ""
            password = ""
        case .usernamePassword:
            value = ""
        }
    }

    private func clearInput() {
        value = ""
        username = ""
        password = ""
        focusedField = nil
    }
}

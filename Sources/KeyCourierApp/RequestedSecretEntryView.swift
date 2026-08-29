import KeyCourierCore
import SwiftUI

enum CredentialEntryMode: String, CaseIterable, Identifiable {
    case single
    case usernamePassword

    var id: Self { self }

    var title: String {
        switch self {
        case .single: "Key or password"
        case .usernamePassword: "Username + password"
        }
    }

    var materialKind: SecretMaterialKind {
        switch self {
        case .single: .single
        case .usernamePassword: .usernamePassword
        }
    }
}

enum CredentialEntry: Sendable {
    case single(Data)
    case usernamePassword(username: String, password: Data)

    var materialKind: SecretMaterialKind {
        switch self {
        case .single: .single
        case .usernamePassword: .usernamePassword
        }
    }
}

struct RequestedSecretEntryView: View {
    @Environment(\.dismiss) private var dismiss
    let model: AppModel
    let request: SecretRequest

    @State private var mode: CredentialEntryMode = .single
    @State private var value = ""
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
                        Text("Paste the key or password here")
                            .font(.headline)
                        Text("\(model.requestCredentialName(request)) for \(model.requestTitle(request))")
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
                        SecureField("Paste key or password", text: $value)
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
                    Text("Requested by \(request.client.rawValue.capitalized). KeyCourier saves it in this Mac's protected Keychain, delivers it to the approved destination, and never returns it to the LLM.")
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Credential needed")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", role: .cancel, action: cancel)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save and deliver", action: submit)
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
        .alert("Credential was not delivered", isPresented: submissionErrorBinding) {
            Button("OK", role: .cancel) { submissionError = nil }
        } message: {
            Text(submissionError ?? "Unknown error")
        }
    }

    private var submissionErrorBinding: Binding<Bool> {
        Binding(get: { submissionError != nil }, set: { if !$0 { submissionError = nil } })
    }

    private func cancel() {
        clearInput()
        dismiss()
    }

    private func submit() {
        let entry: CredentialEntry
        switch mode {
        case .single:
            entry = .single(Data(value.utf8))
        case .usernamePassword:
            entry = .usernamePassword(username: username, password: Data(password.utf8))
        }
        clearInput()
        Task {
            if await model.saveRequestedCredential(entry, for: request) {
                dismiss()
            } else {
                submissionError = model.errorMessage
                model.errorMessage = nil
            }
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

    private func clearInput() {
        value = ""
        username = ""
        password = ""
        focusedField = nil
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
}

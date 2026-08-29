import SwiftUI

struct MobileCredentialsView: View {
    let model: CompanionAppModel
    @State private var presentedSheet: CredentialSheet?

    var body: some View {
        NavigationStack {
            List {
                CredentialSummaryCard(count: model.credentials.count) {
                    presentedSheet = .add
                }
                .listRowBackground(Color.clear)
                .listRowInsets(EdgeInsets(top: 12, leading: 16, bottom: 12, trailing: 16))
                .listRowSeparator(.hidden)

                if model.credentials.isEmpty {
                    ContentUnavailableView {
                        Label("No credentials yet", systemImage: "key")
                    } description: {
                        Text("Add a key or password to send it securely to your paired Mac.")
                    } actions: {
                        Button("Add credential", systemImage: "plus") {
                            presentedSheet = .add
                        }
                        .buttonStyle(.borderedProminent)
                    }
                } else {
                    Section("Saved credentials") {
                        ForEach(model.credentials) { credential in
                            Button {
                                presentedSheet = .edit(credential)
                            } label: {
                                MobileCredentialRow(credential: credential)
                            }
                            .buttonStyle(.plain)
                            .accessibilityHint("Opens a form to replace this credential's value")
                            .listRowBackground(Color.clear)
                            .listRowInsets(EdgeInsets(top: 6, leading: 16, bottom: 6, trailing: 16))
                            .listRowSeparator(.hidden)
                        }
                    }
                }

                if let message = model.statusMessage {
                    Section("Status") {
                        Text(message)
                    }
                }
            }
            .listStyle(.plain)
            .scrollContentBackground(.hidden)
            .background { MobileBackdrop() }
            .refreshable { await model.refresh() }
            .navigationTitle("Credentials")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button("Add credential", systemImage: "plus") {
                        presentedSheet = .add
                    }
                }
            }
            .sheet(item: $presentedSheet) { sheet in
                switch sheet {
                case .add:
                    MobileCredentialEntryView(model: model)
                case .edit(let credential):
                    MobileCredentialEntryView(model: model, credential: credential)
                }
            }
        }
    }
}

private struct CredentialSummaryCard: View {
    let count: Int
    let addCredential: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(alignment: .top, spacing: 16) {
                Image(systemName: "key.shield.fill")
                    .font(.system(size: 30, weight: .semibold))
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(.tint)
                    .frame(width: 52, height: 52)
                    .background(.thinMaterial, in: .rect(cornerRadius: 15))
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 5) {
                    Text("Your private credential vault")
                        .font(.title2.bold())
                    Text("Add a password, API key or login. It is encrypted before leaving this iPhone.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            HStack {
                Label("\(count) saved", systemImage: "lock.fill")
                    .font(.subheadline.weight(.medium))
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Add credential", systemImage: "plus", action: addCredential)
                    .buttonStyle(.borderedProminent)
            }
        }
        .padding(20)
        .mobileSurface()
        .accessibilityElement(children: .contain)
    }
}

private enum CredentialSheet: Identifiable {
    case add
    case edit(CompanionCredentialSummary)

    var id: String {
        switch self {
        case .add:
            "add"
        case .edit(let credential):
            "edit-\(credential.id)"
        }
    }
}

private enum MobileCredentialEntryMode: String, CaseIterable, Identifiable {
    case single
    case usernamePassword

    var id: Self { self }

    var title: String {
        switch self {
        case .single:
            "Key or password"
        case .usernamePassword:
            "Username + password"
        }
    }
}

private struct MobileCredentialRow: View {
    let credential: CompanionCredentialSummary

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "key.fill")
                .foregroundStyle(.tint)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(credential.displayName)
                    .font(.headline)
                Text(MobileSecretKind(rawValue: credential.kind)?.displayName ?? credential.kind)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Image(systemName: "chevron.forward")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.tertiary)
                .accessibilityHidden(true)
        }
        .padding(16)
        .contentShape(.rect)
        .mobileSurface(cornerRadius: 18)
    }
}

private struct MobileCredentialEntryView: View {
    @Environment(\.dismiss) private var dismiss
    let model: CompanionAppModel
    let credential: CompanionCredentialSummary?

    @State private var displayName: String
    @State private var generatedCredentialID: String
    @State private var mode: MobileCredentialEntryMode
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

    init(model: CompanionAppModel, credential: CompanionCredentialSummary? = nil) {
        self.model = model
        self.credential = credential
        _displayName = State(initialValue: credential?.displayName ?? "")
        _generatedCredentialID = State(initialValue: "mobile-\(UUID().uuidString.lowercased())")
        _mode = State(initialValue: Self.mode(for: credential))
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    if let credential {
                        Text(credential.displayName)
                            .font(.headline)
                    } else {
                        DisclosureGroup("Advanced") {
                            TextField("Name (optional)", text: $displayName, prompt: Text("Cloudflare API"))
                                .textInputAutocapitalization(.words)
                                .autocorrectionDisabled()
                            Text("Leave this blank to use a generated name.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }

                    Picker("Format", selection: $mode) {
                        ForEach(MobileCredentialEntryMode.allCases) { mode in
                            Text(mode.title).tag(mode)
                        }
                    }
                    .pickerStyle(.segmented)

                    switch mode {
                    case .single:
                        HStack {
                            SecureField(fieldPrompt, text: $value)
                                .textContentType(.password)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                                .focused($focusedField, equals: .value)
                            PasteButton(payloadType: String.self) { strings in
                                value = strings.first ?? ""
                            }
                            .labelStyle(.iconOnly)
                            .accessibilityLabel("Paste key or password")
                        }
                    case .usernamePassword:
                        TextField("Username", text: $username)
                            .textContentType(.username)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .focused($focusedField, equals: .username)
                        HStack {
                            SecureField("Password", text: $password)
                                .textContentType(.password)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                                .focused($focusedField, equals: .password)
                            PasteButton(payloadType: String.self) { strings in
                                password = strings.first ?? ""
                            }
                            .labelStyle(.iconOnly)
                            .accessibilityLabel("Paste password")
                        }
                    }
                } header: {
                    Text(credential == nil ? "Add credential" : "Replace value")
                } footer: {
                    Text("The credential is encrypted on this iPhone, then cleared from this form before upload.")
                }
            }
            .navigationTitle(credential == nil ? "Add credential" : "Edit credential")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", role: .cancel, action: cancel)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(credential == nil ? "Encrypt and send" : "Replace value", action: submit)
                        .disabled(!canSubmit || model.isWorking)
                }
            }
        }
        .task {
            focusedField = mode == .single ? .value : .username
        }
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

    private var fieldPrompt: String {
        credential == nil ? "Paste key or password" : "Paste replacement key or password"
    }

    private static func mode(for credential: CompanionCredentialSummary?) -> MobileCredentialEntryMode {
        guard let credential else { return .single }
        return credential.materialKind == .usernamePassword
            ? .usernamePassword
            : .single
    }

    private var canSubmit: Bool {
        guard !suggestedID.isEmpty else {
            return false
        }
        switch mode {
        case .single:
            return !value.isEmpty
        case .usernamePassword:
            return !username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !password.isEmpty
        }
    }

    private var suggestedID: String {
        guard credential == nil else { return credential?.secretID ?? "" }
        let source = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !source.isEmpty else { return generatedCredentialID }
        var value = String(source.lowercased().map {
            $0.isASCII && ($0.isLetter || $0.isNumber) ? $0 : "-"
        })
        value = value.split(separator: "-", omittingEmptySubsequences: true).joined(separator: "-")
        guard !value.isEmpty else { return generatedCredentialID }
        return value.count > 64 ? String(value.prefix(64)) : value
    }

    private func effectiveDisplayName(secretID: String) -> String {
        let value = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else {
            let suffix = secretID.suffix(6).uppercased()
            let label = mode == .usernamePassword ? "Username and password" : "Key or password"
            return "\(label) \(suffix)"
        }
        return value
    }

    private var kind: MobileSecretKind {
        if let credential, let existingKind = MobileSecretKind(rawValue: credential.kind) {
            return existingKind
        }
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

    private var submissionErrorBinding: Binding<Bool> {
        Binding(
            get: { submissionError != nil },
            set: { if !$0 { submissionError = nil } }
        )
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
        let secretID = suggestedID
        let displayName = effectiveDisplayName(secretID: secretID)
        let credentialKind = kind
        clearInput()
        Task {
            let saved = await model.addCredential(
                secretID: secretID,
                displayName: displayName,
                kind: credentialKind,
                material: material,
                replacesExisting: credential != nil
            )
            if saved {
                dismiss()
            } else {
                submissionError = model.errorMessage
                model.errorMessage = nil
            }
        }
    }

    private func clearInactiveInput(for mode: MobileCredentialEntryMode) {
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

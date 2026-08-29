import KeyCourierCore
import SwiftUI

struct GuidedSecretEntryView: View {
    @Environment(\.dismiss) private var dismiss
    let model: AppModel
    let destination: GuidedDestination
    @State private var value = ""
    @State private var submissionError: String?

    private var isChangingShortcutCredential: Bool {
        model.secrets.contains { $0.id.rawValue == destination.secretIDValue }
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField("Paste key or password", text: $value)
                        .textContentType(.password)
                } header: {
                    Text("\(destination.displayName) shortcut")
                } footer: {
                    Text("This is the one default used by the short destination command. Other credentials stay separate in your vault and can also be delivered here when explicitly requested.")
                }
            }
            .formStyle(.grouped)
            .navigationTitle(isChangingShortcutCredential ? "Change shortcut credential" : "Set shortcut credential")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", role: .cancel, action: cancel)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(isChangingShortcutCredential ? "Change" : "Save", action: submit)
                        .disabled(value.isEmpty || model.isWorking)
                }
            }
        }
        .frame(minWidth: 440, minHeight: 260)
        .alert(failureTitle, isPresented: submissionErrorBinding) {
            Button("OK", role: .cancel) { submissionError = nil }
        } message: {
            Text(submissionError ?? "Unknown error")
        }
    }

    private var submissionErrorBinding: Binding<Bool> {
        Binding(get: { submissionError != nil }, set: { if !$0 { submissionError = nil } })
    }

    private var failureTitle: String {
        isChangingShortcutCredential ? "Shortcut credential was not changed" : "Shortcut credential was not saved"
    }

    private func cancel() {
        value = ""
        dismiss()
    }

    private func submit() {
        let secret = Data(value.utf8)
        value = ""
        Task {
            if await model.saveSecret(for: destination, value: secret) {
                dismiss()
            } else {
                submissionError = model.errorMessage
                model.errorMessage = nil
            }
        }
    }
}

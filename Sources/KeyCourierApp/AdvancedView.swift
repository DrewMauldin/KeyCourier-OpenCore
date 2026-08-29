import KeyCourierCore
import SwiftUI

struct AdvancedView: View {
    let model: AppModel
    let addCustomSecret: () -> Void
    let addCustomDestination: () -> Void
    @State private var secretToDelete: SecretMetadata?
    @State private var consumerToDelete: ConsumerProfile?

    var body: some View {
        List {
            Section("Saved credentials") {
                ForEach(model.secrets) { secret in
                    SecretTechnicalRow(
                        secret: secret,
                        isBuiltIn: model.isBuiltIn(secret),
                        delete: { secretToDelete = secret }
                    )
                }
                Button("Add custom credential", systemImage: "plus", action: addCustomSecret)
            }

            Section("Registered destinations") {
                ForEach(model.consumers) { consumer in
                    DestinationTechnicalRow(
                        consumer: consumer,
                        isBuiltIn: model.isBuiltIn(consumer),
                        delete: { consumerToDelete = consumer }
                    )
                }
                Button("Add local destination", systemImage: "plus", action: addCustomDestination)
            }

            if !model.requests.isEmpty {
                Section("Pending request details") {
                    ForEach(model.requests) { request in
                        DisclosureGroup(model.requestTitle(request)) {
                            DisclosureGroup("Advanced identifiers") {
                                LabeledContent("Secret ID", value: request.secretID.rawValue)
                                LabeledContent("Consumer ID", value: request.consumerID.rawValue)
                                LabeledContent("Target ID", value: request.targetID.rawValue)
                            }
                        }
                    }
                }
            }
        }
        .navigationTitle("Advanced")
        .confirmationDialog(
            "Delete this credential permanently?",
            isPresented: secretDeleteBinding,
            presenting: secretToDelete
        ) { secret in
            Button("Delete \(secret.displayName)", role: .destructive) {
                secretToDelete = nil
                Task { await model.deleteSecret(secret) }
            }
        } message: { secret in
            Text("This removes \(secret.displayName) from Keychain. Existing destination files are not changed.")
        }
        .confirmationDialog(
            "Delete this destination?",
            isPresented: consumerDeleteBinding,
            presenting: consumerToDelete
        ) { consumer in
            Button("Delete \(consumer.displayName)", role: .destructive) {
                consumerToDelete = nil
                Task { await model.deleteConsumer(consumer) }
            }
        } message: { consumer in
            Text("Future requests for \(consumer.displayName) will fail closed. Existing files are not changed.")
        }
    }

    private var secretDeleteBinding: Binding<Bool> {
        Binding(get: { secretToDelete != nil }, set: { if !$0 { secretToDelete = nil } })
    }

    private var consumerDeleteBinding: Binding<Bool> {
        Binding(get: { consumerToDelete != nil }, set: { if !$0 { consumerToDelete = nil } })
    }
}

private struct SecretTechnicalRow: View {
    let secret: SecretMetadata
    let isBuiltIn: Bool
    let delete: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack {
                Text(secret.displayName).font(.headline)
                Spacer()
                Text(secret.kind.displayName).foregroundStyle(.secondary)
                Button("Delete", systemImage: "trash", role: .destructive, action: delete)
                    .labelStyle(.iconOnly)
                    .help("Delete \(secret.displayName)")
            }
            DisclosureGroup("Advanced") {
                LabeledContent("Secret ID", value: secret.id.rawValue)
                if isBuiltIn {
                    Text("Managed by the guided setup.")
                        .foregroundStyle(.secondary)
                }
            }
        }
        .padding(.vertical, 3)
    }
}

private struct DestinationTechnicalRow: View {
    let consumer: ConsumerProfile
    let isBuiltIn: Bool
    let delete: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack {
                Text(consumer.displayName).font(.headline)
                Spacer()
                if !isBuiltIn {
                    Button("Delete", systemImage: "trash", role: .destructive, action: delete)
                        .labelStyle(.iconOnly)
                        .help("Delete \(consumer.displayName)")
                }
            }
            DisclosureGroup("Advanced") {
                LabeledContent("Consumer ID", value: consumer.id.rawValue)
                LabeledContent("Target ID", value: consumer.targetID.rawValue)
                destinationDetails
            }
        }
        .padding(.vertical, 3)
    }

    @ViewBuilder
    private var destinationDetails: some View {
        switch consumer.destination {
        case .dotenv(let path, let variable):
            LabeledContent("Environment file", value: path)
            LabeledContent("Variable", value: variable)
        case .dotenvLogin(let path, let usernameVariable, let passwordVariable):
            LabeledContent("Environment file", value: path)
            LabeledContent("Username variable", value: usernameVariable)
            LabeledContent("Password variable", value: passwordVariable)
        case .remoteAge(let profile):
            LabeledContent("Encrypted profile", value: profile)
            Text("The host route is loaded from an owner-controlled encrypted delivery profile.")
                .foregroundStyle(.secondary)
        }
    }
}

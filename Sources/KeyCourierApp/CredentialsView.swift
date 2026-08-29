import KeyCourierCore
import SwiftUI

struct CredentialsView: View {
    let model: AppModel
    let addCredential: () -> Void
    let importCredentials: () -> Void
    let editCredential: (SecretMetadata) -> Void

    @State private var searchText = ""
    @State private var secretToDelete: SecretMetadata?

    var body: some View {
        Group {
            if model.secrets.isEmpty {
                ContentUnavailableView {
                    Label("No credentials yet", systemImage: "key")
                } description: {
                    Text("Add a key, password or login. Save as many credentials as you need.")
                } actions: {
                    Button("Add credential", systemImage: "plus", action: addCredential)
                    Button("Import .env", systemImage: "square.and.arrow.down", action: importCredentials)
                }
            } else {
                List {
                    CredentialOverview(
                        total: model.secrets.count,
                        attentionCount: attentionCount,
                        trackedCount: trackedCount
                    )
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets(top: 10, leading: 16, bottom: 10, trailing: 16))

                    ForEach(projectNames, id: \.self) { project in
                        Section(project) {
                            ForEach(credentials(in: project)) { secret in
                                CredentialRow(secret: secret) {
                                    editCredential(secret)
                                }
                                .contextMenu {
                                    Button("Delete", systemImage: "trash", role: .destructive) {
                                        secretToDelete = secret
                                    }
                                }
                            }
                        }
                    }

                }
                .overlay {
                    if filteredSecrets.isEmpty {
                        ContentUnavailableView.search(text: searchText)
                    }
                }
            }
        }
        .navigationTitle("Credentials")
        .searchable(text: $searchText, prompt: "Search credentials")
        .toolbar {
            ToolbarItemGroup {
                Button("Add credential", systemImage: "plus", action: addCredential)
                Button("Import .env file", systemImage: "square.and.arrow.down", action: importCredentials)
            }
        }
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
    }

    private var secretDeleteBinding: Binding<Bool> {
        Binding(get: { secretToDelete != nil }, set: { if !$0 { secretToDelete = nil } })
    }

    private var projectNames: [String] {
        Set(filteredSecrets.map { normalised($0.projectName, fallback: "Personal") }).sorted()
    }

    private func credentials(in project: String) -> [SecretMetadata] {
        filteredSecrets.filter { normalised($0.projectName, fallback: "Personal") == project }
    }

    private var filteredSecrets: [SecretMetadata] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return model.secrets }
        return model.secrets.filter { secret in
            [
                secret.displayName,
                secret.kind.displayName,
                secret.ownerName,
                secret.projectName,
                secret.environmentName
            ]
            .compactMap { $0 }
            .contains { $0.localizedCaseInsensitiveContains(query) }
        }
    }

    private func normalised(_ value: String?, fallback: String) -> String {
        guard let value, !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return fallback
        }
        return value
    }

    private var attentionCount: Int {
        model.secrets.filter { $0.lifecycleStatus().needsAttention }.count
    }

    private var trackedCount: Int {
        model.secrets.filter { $0.lifecycleStatus() != .untracked }.count
    }
}

private struct CredentialOverview: View {
    let total: Int
    let attentionCount: Int
    let trackedCount: Int

    var body: some View {
        HStack(spacing: 18) {
            Image(systemName: "key.shield.fill")
                .font(.title2)
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(.tint)
                .frame(width: 46, height: 46)
                .background(.tint.opacity(0.1), in: .rect(cornerRadius: 13))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text("\(total) saved credential\(total == 1 ? "" : "s")")
                    .font(.headline)
                Text(attentionCount == 0 ? "No rotation or expiry warnings" : "\(attentionCount) need attention")
                    .foregroundStyle(attentionColour)
            }
            Spacer()
            if trackedCount > 0 {
                Label("\(trackedCount) tracked", systemImage: "calendar.badge.checkmark")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(18)
        .background(.regularMaterial, in: .rect(cornerRadius: 18))
        .accessibilityElement(children: .combine)
    }

    private var attentionColour: Color {
        attentionCount == 0 ? .secondary : .orange
    }
}

private struct CredentialRow: View {
    let secret: SecretMetadata
    let edit: () -> Void

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            Image(systemName: statusImage)
                .foregroundStyle(statusColour)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(secret.displayName)
                    .font(.headline)
                Text(summary)
                    .foregroundStyle(.secondary)
                if let owner = secret.ownerName {
                    Text("Owner: \(owner)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            Text(statusText)
                .font(.caption.weight(.medium))
                .foregroundStyle(statusColour)
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(statusColour.opacity(0.1), in: .capsule)
            Button("Edit", systemImage: "pencil", action: edit)
                .help("Edit or replace \(secret.displayName)")
        }
        .padding(.vertical, 4)
    }

    private var summary: String {
        let value = [secret.environmentName, secret.kind.displayName]
            .compactMap { $0 }
            .joined(separator: " · ")
        return value.isEmpty ? "Credential" : value
    }

    private var statusText: String {
        switch secret.lifecycleStatus() {
        case .expired: "Expired"
        case .rotationDue: "Rotate now"
        case .expiringSoon: "Expires soon"
        case .healthy: "On track"
        case .untracked: "Not tracked"
        }
    }

    private var statusImage: String {
        secret.lifecycleStatus().needsAttention ? "exclamationmark.triangle.fill" : "checkmark.circle.fill"
    }

    private var statusColour: Color {
        secret.lifecycleStatus().needsAttention ? .orange : .secondary
    }
}

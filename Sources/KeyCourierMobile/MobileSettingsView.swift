import SwiftUI

struct MobileSettingsView: View {
    let model: CompanionAppModel

    var body: some View {
        NavigationStack {
            List {
                CompanionStatusCard(notificationsEnabled: model.notificationsEnabled)
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets(top: 12, leading: 16, bottom: 12, trailing: 16))
                    .listRowSeparator(.hidden)

                Section("Pairing") {
                    Label("Paired with KeyCourier on Mac", systemImage: "checkmark.shield.fill")
                        .foregroundStyle(.green)
                    Button("Check connection", systemImage: "arrow.clockwise") {
                        Task { await model.refresh() }
                    }
                }

                Section("Notifications") {
                    Label(
                        model.notificationsEnabled ? "Approval notifications are on" : "Approval notifications are off",
                        systemImage: model.notificationsEnabled ? "bell.badge.fill" : "bell.slash"
                    )
                    .foregroundStyle(model.notificationsEnabled ? .green : .secondary)
                    if !model.notificationsEnabled {
                        Button("Enable notifications") {
                            Task { await model.enableNotifications() }
                        }
                    }
                    Text("Notifications contain request metadata only and open KeyCourier for owner authentication.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Section("Security") {
                    Label("Credential values remain end-to-end encrypted", systemImage: "lock.shield.fill")
                        .foregroundStyle(.green)
                    DisclosureGroup("Technical details") {
                        LabeledContent("Approvals", value: "Face ID or passcode")
                        LabeledContent("Decision proof", value: "Ed25519 signature")
                        LabeledContent("Secret handoff", value: "X25519 + ChaChaPoly")
                        LabeledContent("Relay", value: "Private CloudKit database")
                    }
                }

                Section("Help and privacy") {
                    Link("KeyCourier Support", destination: URL(string: "https://keycourier.drewsdigest.com/support/")!)
                    Link("Privacy Policy", destination: URL(string: "https://keycourier.drewsdigest.com/privacy/")!)
                    Text("Never include a credential value or private key in a support request.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                if let message = model.statusMessage {
                    Section("Status") { Text(message) }
                }
            }
            .scrollContentBackground(.hidden)
            .background { MobileBackdrop() }
            .navigationTitle("Settings")
        }
    }
}

private struct CompanionStatusCard: View {
    let notificationsEnabled: Bool

    var body: some View {
        HStack(alignment: .top, spacing: 16) {
            Image(systemName: "iphone.and.arrow.forward")
                .font(.system(size: 30, weight: .semibold))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(.tint)
                .frame(width: 52, height: 52)
                .background(.thinMaterial, in: .rect(cornerRadius: 15))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 5) {
                Text("iPhone companion is ready")
                    .font(.title2.bold())
                Text(notificationsEnabled ? "Paired, protected and ready for approval notifications." : "Paired and protected. Turn on notifications for the fastest approvals.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(20)
        .mobileSurface()
        .accessibilityElement(children: .combine)
    }
}

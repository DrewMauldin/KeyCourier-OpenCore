import KeyCourierCore
import SwiftUI

struct HomeView: View {
    let model: AppModel
    let addCredential: () -> Void
    let manageCredentials: () -> Void
    let copyAgentSetupPrompt: () -> Void

    @State private var didCopySetupPrompt = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                CredentialHero(
                    credentialCount: model.secrets.count,
                    requestCount: model.requests.count,
                    isDeliveryReady: model.guidedConnectionsConfirmed,
                    addCredential: addCredential,
                    manageCredentials: manageCredentials
                )

                SetupChecklistCard(
                    model: model,
                    didCopy: didCopySetupPrompt,
                    copyPrompt: copySetupPrompt
                )

                WorkflowCard()
            }
            .padding(24)
            .frame(maxWidth: 1040)
            .frame(maxWidth: .infinity)
        }
        .background { DashboardBackdrop() }
        .navigationTitle("Home")
    }

    private func copySetupPrompt() {
        copyAgentSetupPrompt()
        withAnimation(.smooth) { didCopySetupPrompt = true }
        Task {
            try? await Task.sleep(for: .seconds(2))
            withAnimation(.smooth) { didCopySetupPrompt = false }
        }
    }
}

private struct CredentialHero: View {
    let credentialCount: Int
    let requestCount: Int
    let isDeliveryReady: Bool
    let addCredential: () -> Void
    let manageCredentials: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            HStack(alignment: .top, spacing: 18) {
                Image(systemName: "key.shield.fill")
                    .font(.system(size: 34, weight: .semibold))
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(.tint)
                    .frame(width: 58, height: 58)
                    .background(.tint.opacity(0.12), in: .rect(cornerRadius: 16))
                    .accessibilityHidden(true)

                VStack(alignment: .leading, spacing: 7) {
                    Text("PRIVATE CREDENTIAL BROKER")
                        .font(.caption.weight(.semibold))
                        .tracking(0.8)
                        .foregroundStyle(.secondary)
                    Text("Add credentials. KeyCourier handles the rest.")
                        .font(.system(.largeTitle, design: .rounded, weight: .bold))
                    Text("Save each password, API key or login once. Your AI can request it, but only you can approve where it goes.")
                        .font(.title3)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            HStack(spacing: 10) {
                Button("Add credential", systemImage: "plus", action: addCredential)
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                if credentialCount > 0 {
                    Button("Manage credentials", systemImage: "key", action: manageCredentials)
                        .controlSize(.large)
                }
            }

            HStack(spacing: 10) {
                MetricPill(icon: "key.fill", value: "\(credentialCount)", label: "saved")
                MetricPill(
                    icon: requestCount == 0 ? "checkmark.shield.fill" : "bell.badge.fill",
                    value: "\(requestCount)",
                    label: requestCount == 1 ? "approval" : "approvals",
                    colour: requestCount == 0 ? .green : .orange
                )
                MetricPill(
                    icon: isDeliveryReady ? "network.badge.shield.half.filled" : "network.slash",
                    value: "Delivery",
                    label: isDeliveryReady ? "ready" : "not ready",
                    colour: isDeliveryReady ? .green : .secondary
                )
            }
        }
        .padding(28)
        .dashboardSurface()
        .accessibilityElement(children: .contain)
    }
}

private struct MetricPill: View {
    let icon: String
    let value: String
    let label: String
    var colour: Color = .accentColor

    var body: some View {
        Label {
            Text("\(value) \(label)")
                .font(.callout.weight(.medium))
        } icon: {
            Image(systemName: icon)
                .foregroundStyle(colour)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 7)
        .background(.thinMaterial, in: .capsule)
        .accessibilityElement(children: .combine)
    }
}

private struct WorkflowCard: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            DashboardSectionHeader(
                title: "The whole workflow",
                subtitle: "Three small steps, with no technical form to complete."
            )
            WorkflowStep(number: 1, icon: "square.and.pencil", title: "Add it", detail: "Paste a key or password.")
            WorkflowStep(number: 2, icon: "sparkles", title: "Your AI requests it", detail: "The value stays hidden.")
            WorkflowStep(number: 3, icon: "checkmark.shield", title: "You approve", detail: "Review the destination and allow or decline.")
        }
        .padding(22)
        .frame(maxWidth: .infinity, alignment: .leading)
        .dashboardSurface()
    }
}

private struct WorkflowStep: View {
    let number: Int
    let icon: String
    let title: String
    let detail: String

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.body.weight(.semibold))
                .foregroundStyle(.tint)
                .frame(width: 34, height: 34)
                .background(.tint.opacity(0.1), in: .circle)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text("\(number). \(title)")
                    .font(.headline)
                Text(detail)
                    .foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
    }
}

private struct SetupChecklistCard: View {
    let model: AppModel
    let didCopy: Bool
    let copyPrompt: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack(alignment: .top, spacing: 16) {
                DashboardSectionHeader(
                    title: "AI setup checklist",
                    subtitle: "Your AI handles safe connection setup. You only add credentials and approve requests."
                )
                Spacer(minLength: 12)
                ChecklistLiveBadge(isChecking: model.isTestingRemoteConnections)
            }

            HStack(spacing: 8) {
                AgentChip(name: "Codex", icon: "terminal")
                AgentChip(name: "Claude", icon: "text.bubble")
                AgentChip(name: "OpenCode", icon: "chevron.left.forwardslash.chevron.right")
            }

            ViewThatFits(in: .horizontal) {
                HStack(spacing: 18) { responsibilityLabels }
                VStack(alignment: .leading, spacing: 8) { responsibilityLabels }
            }

            LazyVGrid(columns: [GridItem(.adaptive(minimum: 260), spacing: 12)], spacing: 12) {
                ForEach(model.destinationSummaries) { summary in
                    DestinationSetupRow(
                        summary: summary,
                        connectionState: model.connectionState(for: summary.destination),
                        hasConfigurationIssue: model.remoteProfileConfigurationIssue
                    )
                }
            }

            ViewThatFits(in: .horizontal) {
                HStack(spacing: 10) { checklistActions }
                VStack(alignment: .leading, spacing: 10) { checklistActions }
            }

            HStack(spacing: 8) {
                Image(systemName: "clock.arrow.circlepath")
                    .accessibilityHidden(true)
                if let date = model.lastRemoteConnectionCheckAt {
                    Text("Last content-free safety check \(date, style: .relative).")
                } else {
                    Text("Safety checks start automatically when your AI finishes a destination.")
                }
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        }
        .padding(22)
        .frame(maxWidth: .infinity, alignment: .leading)
        .dashboardSurface()
    }

    @ViewBuilder
    private var responsibilityLabels: some View {
        Label("AI: setup and diagnostics", systemImage: "sparkles")
        Label("You: credentials and approvals", systemImage: "person.badge.shield.checkmark")
    }

    @ViewBuilder
    private var checklistActions: some View {
        Button(
            didCopy ? "Approved prompt copied" : "Copy approved setup prompt",
            systemImage: didCopy ? "checkmark" : "doc.on.doc",
            action: copyPrompt
        )
        .buttonStyle(.borderedProminent)
        .controlSize(.large)
        .accessibilityHint("Copies owner-reviewed setup instructions for an AI assistant")

        if model.hasConfiguredRemoteDestinations {
            Button("Check now", systemImage: "arrow.clockwise") {
                Task { await model.testRemoteConnections() }
            }
            .buttonStyle(.bordered)
            .controlSize(.large)
            .disabled(model.isTestingRemoteConnections)
            .accessibilityHint("Runs content-free checks for configured destinations")
        }
    }
}

private struct ChecklistLiveBadge: View {
    let isChecking: Bool

    var body: some View {
        Label(isChecking ? "Checking now" : "Live", systemImage: isChecking ? "arrow.triangle.2.circlepath" : "dot.radiowaves.left.and.right")
            .font(.caption.weight(.semibold))
            .foregroundStyle(isChecking ? Color.accentColor : Color.green)
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(.thinMaterial, in: .capsule)
            .accessibilityLabel(isChecking ? "Checking destinations now" : "Destination status updates automatically")
    }
}

private struct AgentChip: View {
    let name: String
    let icon: String

    var body: some View {
        Label(name, systemImage: icon)
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(.quaternary, in: .capsule)
    }
}

private struct DashboardSectionHeader: View {
    let title: String
    let subtitle: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.title2.weight(.semibold))
            Text(subtitle)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .combine)
    }
}

private struct DestinationSetupRow: View {
    let summary: DestinationSummary
    let connectionState: RemoteConnectionState?
    let hasConfigurationIssue: Bool

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: destinationImage)
                .font(.title3.weight(.semibold))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(.tint)
                .frame(width: 42, height: 42)
                .background(.tint.opacity(0.1), in: .rect(cornerRadius: 12))
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 4) {
                Text(destinationName)
                    .font(.headline)
                    .lineLimit(2)
                Text(status.detail(for: summary.destination))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer(minLength: 8)

            if status == .checking {
                ProgressView()
                    .controlSize(.small)
                    .accessibilityLabel("Checking \(destinationName)")
            } else {
                Label(status.title, systemImage: status.systemImage)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(status.colour)
                    .labelStyle(.titleAndIcon)
                    .fixedSize()
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, minHeight: 88, alignment: .leading)
        .background(.thinMaterial, in: .rect(cornerRadius: 18))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(destinationName), \(status.title), \(status.detail(for: summary.destination))")
    }

    private var status: DestinationSetupStatus {
        DestinationSetupStatus(
            summary: summary,
            connectionState: connectionState,
            hasConfigurationIssue: hasConfigurationIssue
        )
    }

    private var destinationImage: String {
        switch summary.destination {
        case .thisMac: "laptopcomputer"
        case .macMini: "macmini"
        case .vps: "server.rack"
        case .cloudMemoryProjection: "arrow.triangle.2.circlepath"
        }
    }

    private var destinationName: String {
        switch summary.destination {
        case .cloudMemoryProjection: "Cloud Memory"
        default: summary.destination.displayName
        }
    }

}

private enum DestinationSetupStatus: Equatable {
    case waitingForAI
    case queued
    case checking
    case ready
    case needsAttention

    init(
        summary: DestinationSummary,
        connectionState: RemoteConnectionState?,
        hasConfigurationIssue: Bool
    ) {
        switch summary.registration {
        case .conflict:
            self = .needsAttention
        case .missing:
            self = .waitingForAI
        case .registered:
            if summary.destination == .thisMac {
                self = .ready
            } else if hasConfigurationIssue {
                self = .needsAttention
            } else {
                self = switch connectionState {
                case nil: .waitingForAI
                case .notTested: .queued
                case .checking: .checking
                case .connected: .ready
                case .needsAttention: .needsAttention
                }
            }
        }
    }

    var title: String {
        switch self {
        case .waitingForAI: "Waiting for AI"
        case .queued: "Queued"
        case .checking: "Checking"
        case .ready: "Ready"
        case .needsAttention: "Needs attention"
        }
    }

    var systemImage: String {
        switch self {
        case .waitingForAI: "circle.dashed"
        case .queued: "clock"
        case .checking: "arrow.triangle.2.circlepath"
        case .ready: "checkmark.circle.fill"
        case .needsAttention: "exclamationmark.triangle.fill"
        }
    }

    var colour: Color {
        switch self {
        case .ready: .green
        case .needsAttention: .orange
        case .checking: .accentColor
        case .waitingForAI, .queued: .secondary
        }
    }

    func detail(for destination: GuidedDestination) -> String {
        switch self {
        case .waitingForAI:
            destination == .cloudMemoryProjection
                ? "Your AI can configure this when a workflow needs it."
                : "Your AI has not finished this destination yet."
        case .queued:
            "A content-free safety check will run automatically."
        case .checking:
            "KeyCourier is checking the destination without sending a credential."
        case .ready:
            destination == .thisMac
                ? "Available for approved local requests."
                : "Available for approved requests. No credential was sent during setup."
        case .needsAttention:
            "The safe setup or connection check failed. Ask your AI to diagnose it."
        }
    }
}

private struct DashboardBackdrop: View {
    var body: some View {
        LinearGradient(
            colors: [
                Color.accentColor.opacity(0.12),
                Color.indigo.opacity(0.05),
                Color.clear
            ],
            startPoint: .topLeading,
            endPoint: .bottomTrailing
        )
        .ignoresSafeArea()
    }
}

private struct DashboardSurface: ViewModifier {
    let cornerRadius: CGFloat

    @ViewBuilder
    func body(content: Content) -> some View {
        if #available(macOS 26.0, *) {
            content
                .glassEffect(.regular, in: .rect(cornerRadius: cornerRadius))
        } else {
            content
                .background(.regularMaterial, in: .rect(cornerRadius: cornerRadius))
                .overlay {
                    RoundedRectangle(cornerRadius: cornerRadius)
                        .stroke(.primary.opacity(0.08), lineWidth: 1)
                }
        }
    }
}

private extension View {
    func dashboardSurface(cornerRadius: CGFloat = 24) -> some View {
        modifier(DashboardSurface(cornerRadius: cornerRadius))
    }
}

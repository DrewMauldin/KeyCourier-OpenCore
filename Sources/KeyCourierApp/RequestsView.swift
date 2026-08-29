import KeyCourierCore
import SwiftUI

struct RequestsView: View {
    let model: AppModel
    let pasteSecret: (SecretRequest) -> Void

    var body: some View {
        Group {
            if model.requests.isEmpty {
                ContentUnavailableView(
                    "No approvals waiting",
                    systemImage: "checkmark.shield.fill",
                    description: Text("You are all caught up. New AI requests will appear here with their credential, destination and reason.")
                )
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 14) {
                        RequestSummary(count: model.requests.count)
                        ForEach(model.requests) { request in
                            RequestCard(model: model, request: request) {
                                pasteSecret(request)
                            }
                        }
                    }
                    .padding(24)
                    .frame(maxWidth: 900)
                    .frame(maxWidth: .infinity)
                }
            }
        }
        .background {
            LinearGradient(
                colors: [Color.accentColor.opacity(0.08), Color.clear],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            .ignoresSafeArea()
        }
        .navigationTitle("Approvals")
    }
}

private struct RequestSummary: View {
    let count: Int

    var body: some View {
        HStack(spacing: 16) {
            Image(systemName: "bell.badge.fill")
                .font(.system(size: 28, weight: .semibold))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(.tint)
                .frame(width: 52, height: 52)
                .background(.tint.opacity(0.1), in: .rect(cornerRadius: 15))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text("\(count) approval\(count == 1 ? "" : "s") waiting")
                    .font(.title2.bold())
                Text("Review what was requested and where it will go. KeyCourier never reveals the value to the AI.")
                    .foregroundStyle(.secondary)
            }
        }
        .padding(20)
        .requestSurface()
        .accessibilityElement(children: .combine)
    }
}

private struct RequestCard: View {
    let model: AppModel
    let request: SecretRequest
    let pasteSecret: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .top, spacing: 14) {
                Image(systemName: "shippingbox.fill")
                    .font(.title2)
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(.tint)
                    .frame(width: 42, height: 42)
                    .background(.tint.opacity(0.1), in: .rect(cornerRadius: 12))
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 4) {
                    Text(model.requestCredentialName(request))
                        .font(.title3.bold())
                    Text("to \(model.requestTitle(request))")
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Text(request.client.rawValue.capitalized)
                    .font(.caption.weight(.semibold))
                    .padding(.horizontal, 9)
                    .padding(.vertical, 5)
                    .background(.quaternary, in: .capsule)
                    .help("The requesting app supplies this name. KeyCourier still requires your approval.")
            }

            Text(request.reason)
                .font(.body)
                .fixedSize(horizontal: false, vertical: true)

            HStack {
                Label(
                    "Expires \(request.expiresAt.formatted(date: .omitted, time: .shortened))",
                    systemImage: "clock"
                )
                .font(.callout)
                .foregroundStyle(.secondary)
                Spacer()
                Button("Decline", role: .destructive) {
                    Task { await model.deny(request) }
                }
                if model.hasSecret(for: request) {
                    Button("Allow delivery") {
                        Task { await model.approve(request) }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(model.isWorking)
                } else {
                    Button("Paste key or password", action: pasteSecret)
                        .buttonStyle(.borderedProminent)
                }
            }
        }
        .padding(20)
        .requestSurface(cornerRadius: 20)
        .accessibilityElement(children: .contain)
    }
}

private struct RequestSurface: ViewModifier {
    let cornerRadius: CGFloat

    @ViewBuilder
    func body(content: Content) -> some View {
        if #available(macOS 26.0, *) {
            content.glassEffect(.regular, in: .rect(cornerRadius: cornerRadius))
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
    func requestSurface(cornerRadius: CGFloat = 22) -> some View {
        modifier(RequestSurface(cornerRadius: cornerRadius))
    }
}

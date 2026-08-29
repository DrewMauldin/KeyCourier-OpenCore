import SwiftUI

struct CompanionRootView: View {
    @Bindable var model: CompanionAppModel

    var body: some View {
        Group {
            switch model.pairingState {
            case .checking:
                ProgressView("Checking KeyCourier pairing…")
            case .unpaired, .denied, .unavailable:
                PairingView(model: model)
            case .pending:
                PendingPairingView(model: model)
            case .verificationNeeded(let code):
                PairingVerificationView(model: model, code: code)
            case .paired:
                companionTabs
            }
        }
        .alert("KeyCourier", isPresented: errorBinding) {
            Button("OK", role: .cancel) { model.errorMessage = nil }
        } message: {
            Text(model.errorMessage ?? "Unknown error")
        }
    }

    @ViewBuilder
    private var companionTabs: some View {
        if #available(iOS 18.0, *) {
            ModernCompanionTabs(model: model)
        } else {
            TabView {
                MobileRequestsView(model: model)
                    .tabItem { Label("Approvals", systemImage: "checkmark.shield") }
                    .badge(model.requests.count)
                MobileCredentialsView(model: model)
                    .tabItem { Label("Credentials", systemImage: "key") }
                MobileSettingsView(model: model)
                    .tabItem { Label("Settings", systemImage: "gearshape") }
            }
        }
    }

    private var errorBinding: Binding<Bool> {
        Binding(
            get: { model.errorMessage != nil },
            set: { if !$0 { model.errorMessage = nil } }
        )
    }
}

@available(iOS 18.0, *)
private struct ModernCompanionTabs: View {
    let model: CompanionAppModel

    @ViewBuilder
    var body: some View {
        if #available(iOS 26.0, *) {
            tabs
                .tabBarMinimizeBehavior(.onScrollDown)
        } else {
            tabs
        }
    }

    private var tabs: some View {
        TabView {
            Tab("Approvals", systemImage: "checkmark.shield") {
                MobileRequestsView(model: model)
            }
            .badge(model.requests.count)
            Tab("Credentials", systemImage: "key") {
                MobileCredentialsView(model: model)
            }
            Tab("Settings", systemImage: "gearshape") {
                MobileSettingsView(model: model)
            }
        }
    }
}

private struct PairingVerificationView: View {
    let model: CompanionAppModel
    let code: String

    var body: some View {
        NavigationStack {
            List {
                Section("Compare on both devices") {
                    Text(code)
                        .font(.system(.largeTitle, design: .monospaced, weight: .semibold))
                        .frame(maxWidth: .infinity)
                        .textSelection(.enabled)
                        .accessibilityLabel("Pairing code \(code)")
                    Text("Open KeyCourier Settings on the Mac. Continue only if its pairing code is exactly the same.")
                }
                Section {
                    Button("Codes match", systemImage: "checkmark.shield") {
                        Task { await model.confirmPairingCode() }
                    }
                    .buttonStyle(.borderedProminent)
                    Button("Check again", systemImage: "arrow.clockwise") {
                        Task { await model.refresh() }
                    }
                }
            }
            .navigationTitle("Verify pairing")
        }
    }
}

private struct PairingView: View {
    let model: CompanionAppModel

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Label("Approve requests with Face ID", systemImage: "faceid")
                    Label("Receive private CloudKit notifications", systemImage: "bell.badge")
                    Label("Send credentials encrypted to your Mac", systemImage: "lock.iphone")
                } header: {
                    Text("KeyCourier on iPhone")
                } footer: {
                    Text("Pairing never gives an AI client the credential value. The Mac remains the delivery and policy authority.")
                }

                Section {
                    Button("Register this iPhone", systemImage: "iphone") {
                        Task { await model.registerThisDevice() }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(model.isWorking)
                    Button("Check again", systemImage: "arrow.clockwise") {
                        Task { await model.refresh() }
                    }
                }

                if let message = model.statusMessage {
                    Section("Status") { Text(message) }
                }
            }
            .navigationTitle("KeyCourier")
        }
    }
}

private struct PendingPairingView: View {
    let model: CompanionAppModel

    var body: some View {
        ContentUnavailableView {
            Label("Approve on your Mac", systemImage: "macbook.and.iphone")
        } description: {
            Text("Open KeyCourier > Settings > iPhone companion, confirm this iPhone, then check again.")
        } actions: {
            Button("Check pairing", systemImage: "arrow.clockwise") {
                Task { await model.refresh() }
            }
            .buttonStyle(.borderedProminent)
        }
    }
}

struct MobileBackdrop: View {
    var body: some View {
        LinearGradient(
            colors: [
                Color.accentColor.opacity(0.14),
                Color.indigo.opacity(0.06),
                Color.clear
            ],
            startPoint: .topLeading,
            endPoint: .bottomTrailing
        )
        .ignoresSafeArea()
    }
}

private struct MobileSurfaceModifier: ViewModifier {
    let cornerRadius: CGFloat

    @ViewBuilder
    func body(content: Content) -> some View {
        if #available(iOS 26.0, *) {
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

extension View {
    func mobileSurface(cornerRadius: CGFloat = 22) -> some View {
        modifier(MobileSurfaceModifier(cornerRadius: cornerRadius))
    }
}

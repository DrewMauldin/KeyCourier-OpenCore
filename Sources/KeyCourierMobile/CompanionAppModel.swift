import Foundation
import LocalAuthentication
import Observation
import UIKit
import UserNotifications

enum MobilePairingState: Equatable {
    case checking
    case unpaired
    case pending
    case verificationNeeded(String)
    case paired
    case denied
    case unavailable
}

@MainActor
@Observable
final class CompanionAppModel {
    private(set) var pairingState: MobilePairingState = .checking
    private(set) var requests: [CompanionRequestSummary] = []
    private(set) var credentials: [CompanionCredentialSummary] = []
    private(set) var notificationsEnabled = false
    private(set) var isWorking = false
    private(set) var statusMessage: String?
    var errorMessage: String?

    private let cloud: any CompanionCloudServing
    private let keyStore = CompanionDeviceKeyStore()
    private let ownerAuthorizer = MobileOwnerAuthorizer()
    private let usesScreenshotFixture: Bool
    private var registration: CompanionDeviceRegistration?

    init(cloud: any CompanionCloudServing = CloudKitCompanionStore()) {
        self.cloud = cloud
#if DEBUG
        usesScreenshotFixture = ProcessInfo.processInfo.arguments.contains("-KeyCourierScreenshotFixture")
#else
        usesScreenshotFixture = false
#endif
        if usesScreenshotFixture {
            configureScreenshotFixture()
        }
    }

    func refresh() async {
        guard !usesScreenshotFixture else { return }
        do {
            try await cloud.requireAvailableAccount()
            let identity = try keyStore.loadOrCreate()
            registration = try await cloud.deviceRegistration(id: identity.id)
            switch registration?.status {
            case nil:
                pairingState = .unpaired
                requests = []
                credentials = []
            case .pending:
                pairingState = .pending
                requests = []
                credentials = []
            case .approved:
                guard let registration,
                      let macPublicKey = registration.macKeyAgreementPublicKey,
                      let macSigningPublicKey = registration.macSigningPublicKey,
                      macPublicKey.count == 32,
                      macSigningPublicKey.count == 32 else {
                    throw CompanionProtocolError.invalidRecord
                }
                if try keyStore.verifiedMacPublicKey() == macPublicKey,
                   try keyStore.verifiedMacSigningPublicKey() == macSigningPublicKey {
                    pairingState = .paired
                    let pendingRequests = try await cloud.pendingRequests(at: Date())
                    for request in pendingRequests {
                        try CompanionCrypto.verify(
                            request,
                            signingPublicKey: macSigningPublicKey
                        )
                    }
                    requests = pendingRequests
                    credentials = try await cloud.credentialSummaries()
                    try? await UNUserNotificationCenter.current().setBadgeCount(requests.count)
                } else {
                    pairingState = .verificationNeeded(try CompanionCrypto.pairingCode(for: registration))
                    requests = []
                    credentials = []
                }
            case .denied:
                pairingState = .denied
                requests = []
                credentials = []
            }
            notificationsEnabled = await notificationIsAuthorised()
        } catch {
            pairingState = .unavailable
            requests = []
            credentials = []
            errorMessage = error.localizedDescription
        }
    }

    func registerThisDevice() async {
        isWorking = true
        defer { isWorking = false }
        do {
            try await cloud.requireAvailableAccount()
            let identity = try keyStore.loadOrCreate()
            try keyStore.clearVerifiedMacPublicKey()
            let registration = try CompanionCrypto.registration(
                deviceID: identity.id,
                deviceName: UIDevice.current.name,
                keys: identity.keys
            )
            try await cloud.saveDeviceRegistration(registration)
            self.registration = registration
            pairingState = .pending
            statusMessage = "Registration sent. Approve this iPhone in KeyCourier Settings on the Mac."
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func confirmPairingCode() async {
        do {
            guard let registration,
                  registration.status == .approved,
                  let macPublicKey = registration.macKeyAgreementPublicKey,
                  let macSigningPublicKey = registration.macSigningPublicKey else {
                throw CompanionProtocolError.invalidRecord
            }
            try await ownerAuthorizer.authorize(reason: "Confirm the KeyCourier pairing code")
            try keyStore.saveVerifiedMacPublicKeys(
                agreement: macPublicKey,
                signing: macSigningPublicKey
            )
            pairingState = .paired
            statusMessage = "Pairing verified. This iPhone can now approve and encrypt credentials."
            await refresh()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func decide(_ action: CompanionDecisionAction, request: CompanionRequestSummary) async {
        isWorking = true
        defer { isWorking = false }
        do {
            guard pairingState == .paired else { throw CompanionProtocolError.deviceNotPaired }
            guard let macSigningPublicKey = try keyStore.verifiedMacSigningPublicKey() else {
                throw CompanionProtocolError.deviceNotPaired
            }
            try CompanionCrypto.verify(request, signingPublicKey: macSigningPublicKey)
            try await ownerAuthorizer.authorize(
                reason: action == .approve
                    ? "Approve KeyCourier credential delivery"
                    : "Decline the KeyCourier request"
            )
            let identity = try keyStore.loadOrCreate()
            let decision = try CompanionCrypto.sign(
                CompanionDecision(
                    requestID: request.id,
                    requestDigest: try request.digest(),
                    deviceID: identity.id,
                    action: action
                ),
                keys: identity.keys
            )
            try await cloud.saveDecision(decision)
            requests.removeAll { $0.id == request.id }
            try? await UNUserNotificationCenter.current().setBadgeCount(requests.count)
            statusMessage = action == .approve
                ? "Approval sent securely to the Mac."
                : "Request declined."
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func addCredential(
        secretID: String,
        displayName: String,
        kind: MobileSecretKind,
        value: Data,
        replacesExisting: Bool = false
    ) async -> Bool {
        await addCredential(
            secretID: secretID,
            displayName: displayName,
            kind: kind,
            material: .single(value),
            replacesExisting: replacesExisting
        )
    }

    func addCredential(
        secretID: String,
        displayName: String,
        kind: MobileSecretKind,
        material: CompanionCredentialMaterial,
        replacesExisting: Bool = false
    ) async -> Bool {
        isWorking = true
        defer { isWorking = false }
        do {
            guard pairingState == .paired,
                  let macPublicKey = registration?.macKeyAgreementPublicKey else {
                throw CompanionProtocolError.deviceNotPaired
            }
            try await ownerAuthorizer.authorize(reason: "Encrypt this credential for KeyCourier on the Mac")
            let payload = try CompanionSecretPayload(
                secretID: secretID,
                displayName: displayName,
                kind: kind.rawValue,
                material: material,
                replacesExisting: replacesExisting
            )
            let identity = try keyStore.loadOrCreate()
            let envelope = try CompanionCrypto.seal(
                payload,
                deviceID: identity.id,
                recipientPublicKey: macPublicKey,
                signingKeys: identity.keys
            )
            try await cloud.saveSecretEnvelope(envelope)
            statusMessage = "Encrypted credential sent. The Mac will import it while KeyCourier is open and unlocked."
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    func enableNotifications() async {
        do {
            notificationsEnabled = try await UNUserNotificationCenter.current()
                .requestAuthorization(options: [.alert, .sound, .badge])
            guard notificationsEnabled else {
                errorMessage = "Notifications are off. Enable them in iPhone Settings."
                return
            }
            UIApplication.shared.registerForRemoteNotifications()
            try await cloud.ensureRequestSubscription()
            statusMessage = "Approval notifications are on."
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func notificationIsAuthorised() async -> Bool {
        let status = await UNUserNotificationCenter.current().notificationSettings().authorizationStatus
        return status == .authorized || status == .provisional
    }

    private func configureScreenshotFixture() {
        do {
            let now = Calendar.current.startOfDay(for: Date())
                .addingTimeInterval(9 * 60 * 60 + 41 * 60)
            pairingState = .paired
            notificationsEnabled = true
            requests = [
                try CompanionRequestSummary(
                    requestID: UUID(),
                    clientName: "Codex",
                    credentialName: "Cloudflare API",
                    destinationName: "Production deploy",
                    reason: "Publish the reviewed website update",
                    createdAt: now,
                    expiresAt: now.addingTimeInterval(15 * 60)
                )
            ]
            credentials = [
                try CompanionCredentialSummary(
                    secretID: "cloudflare-api",
                    displayName: "Cloudflare API",
                    kind: MobileSecretKind.apiKey.rawValue
                ),
                try CompanionCredentialSummary(
                    secretID: "hosting-login",
                    displayName: "Hosting login",
                    kind: MobileSecretKind.password.rawValue,
                    materialKind: .usernamePassword
                )
            ]
        } catch {
            assertionFailure("Invalid KeyCourier screenshot fixture: \(error)")
        }
    }
}

enum MobileSecretKind: String, CaseIterable, Identifiable {
    case apiKey
    case password
    case token
    case other

    var id: Self { self }

    var displayName: String {
        switch self {
        case .apiKey: "API key"
        case .password: "Password"
        case .token: "Token"
        case .other: "Other"
        }
    }
}

private struct MobileOwnerAuthorizer {
    func authorize(reason: String) async throws {
        let context = LAContext()
        context.localizedReason = reason
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            throw error ?? CompanionProtocolError.invalidSignature
        }
        guard try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) else {
            throw CompanionProtocolError.invalidSignature
        }
    }
}

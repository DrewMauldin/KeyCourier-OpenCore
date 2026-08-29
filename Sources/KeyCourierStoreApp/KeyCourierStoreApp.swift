import AppKit
import CryptoKit
import KeyCourierCore
import Observation
import OSLog
import SwiftUI
import UserNotifications

@main
struct KeyCourierStoreApp: App {
    @NSApplicationDelegateAdaptor(StoreAppDelegate.self) private var appDelegate

    var body: some Scene {
        WindowGroup("KeyCourier", id: "main") {
            StoreRootView(model: appDelegate.model)
        }
        .defaultSize(width: 560, height: 460)
    }
}

@MainActor
private final class StoreAppDelegate: NSObject, NSApplicationDelegate {
    let model = StoreBridgeModel()

    func applicationDidFinishLaunching(_ notification: Notification) {
        model.startMonitoring()
    }

    func applicationWillTerminate(_ notification: Notification) {
        model.stopMonitoring()
    }
}

@MainActor
private struct StoreRequestNotificationService {
    private let center = UNUserNotificationCenter.current()

    func notifyIfNeeded(for requestID: UUID) async {
        var settings = await center.notificationSettings()
        if settings.authorizationStatus == .notDetermined {
            _ = try? await center.requestAuthorization(options: [.alert, .sound])
            settings = await center.notificationSettings()
        }
        guard settings.authorizationStatus == .authorized
                || settings.authorizationStatus == .provisional else {
            return
        }
        let content = UNMutableNotificationContent()
        content.title = "Credential needed"
        content.body = "An authenticated request needs a credential. Open KeyCourier to continue."
        content.sound = .default
        let request = UNNotificationRequest(
            identifier: "missing-credential-\(requestID.uuidString.lowercased())",
            content: content,
            trigger: nil
        )
        try? await center.add(request)
    }
}

private enum StoreCredentialStorageError: LocalizedError {
    case migrationRequired

    var errorDescription: String? {
        switch self {
        case .migrationRequired:
            return "A protected credential with this ID already exists outside the Store. Open the main KeyCourier app to recover or replace it before adding this credential here."
        }
    }
}

@MainActor
@Observable
private final class StoreBridgeModel {
    private(set) var pairings: [StoreBridgePairing] = []
    private(set) var trustedBridgeID: UUID?
    private(set) var pendingRequestCount = 0
    private(set) var pendingRequests: [StorePendingRequest] = []
    private(set) var secrets: [SecretMetadata] = []
    private(set) var statusMessage = "Looking for a bridge…"
    private(set) var errorMessage: String?
    private(set) var isTrustingBridge = false
    private(set) var processingRequestIDs: Set<UUID> = []
    private(set) var companionConfiguration = CompanionConfiguration()
    private(set) var companionRegistrations: [CompanionDeviceRegistration] = []
    private(set) var companionPairingCode: String?
    private(set) var companionStatusMessage: String?
    private(set) var companionApprovalDefault = false
    private(set) var missingCredentialRequest: StorePendingRequest?

    private let queue: BridgeQueue?
    private let identityStore = BridgeKeychainIdentityStore(role: .store)
    private let peerStore = BridgePinnedPeerStore(role: .store)
    private let ownerAuthorizer: any OwnerPresenceAuthorizing
    private let secretStore: KeychainSecretStore
    private let metadataStore: FileMetadataStore
    private let receiptStore: FileReceiptStore
    private let companionStore: FileCompanionConfigurationStore
    private let companionCloud: any CompanionCloudServing
    private let companionKeyStore = CompanionDeviceKeyStore()
    private let logger = Logger(
        subsystem: "com.drewsdigest.KeyCourier",
        category: "StoreBridge"
    )
    private var identity: BridgeIdentity?
    private var companionLastRefresh = Date.distantPast
    private var isProcessingCompanion = false
    private var promptedMissingCredentialRequestIDs = Set<UUID>()
    private var notifiedMissingCredentialRequestIDs = Set<UUID>()
    private var monitoringTask: Task<Void, Never>?
    private let notificationService = StoreRequestNotificationService()

    init(
        root: URL? = nil,
        ownerAuthorizer: any OwnerPresenceAuthorizing = LocalOwnerPresenceAuthorizer(),
        secretStore: KeychainSecretStore = KeychainSecretStore(),
        companionCloud: any CompanionCloudServing = CloudKitCompanionStore()
    ) {
        let metadataRoot: URL
        let metadataTrustedAnchor: URL?
        let receiptRoot: URL
        let receiptTrustedAnchor: URL?
        let companionTrustedAnchor: URL?
        if let root {
            queue = BridgeQueue(root: root)
            metadataRoot = root.appending(path: "StoreMetadata")
            metadataTrustedAnchor = nil
            receiptRoot = root.appending(path: "StoreReceipts")
            receiptTrustedAnchor = nil
            companionTrustedAnchor = nil
        } else {
            let applicationSupport = FileManager.default.urls(
                for: .applicationSupportDirectory,
                in: .userDomainMask
            ).first!
            let storeRoot = applicationSupport.appending(
                path: "KeyCourier",
                directoryHint: .isDirectory
            )
            metadataRoot = storeRoot.appending(path: "Metadata")
            metadataTrustedAnchor = applicationSupport
            receiptRoot = storeRoot.appending(path: "Receipts")
            receiptTrustedAnchor = applicationSupport
            companionTrustedAnchor = applicationSupport
            if let groupContainer = FileManager.default.containerURL(
                forSecurityApplicationGroupIdentifier: BridgeSharedContainer.groupIdentifier
            ) {
                queue = BridgeQueue(
                    root: groupContainer.appending(
                        path: "KeyCourierBridge",
                        directoryHint: .isDirectory
                    ),
                    trustedAnchor: groupContainer
                )
            } else {
                queue = nil
            }

            let sharedMetadataStore = FileMetadataStore(
                root: metadataRoot,
                trustedAnchor: metadataTrustedAnchor
            )
            let legacyMetadataStore = FileMetadataStore(
                root: storeRoot.appending(path: "StoreMetadata"),
                trustedAnchor: metadataTrustedAnchor
            )
            _ = try? sharedMetadataStore.migrateSecretsIfEmpty(from: legacyMetadataStore)
        }
        metadataStore = FileMetadataStore(root: metadataRoot, trustedAnchor: metadataTrustedAnchor)
        receiptStore = FileReceiptStore(root: receiptRoot, trustedAnchor: receiptTrustedAnchor)
        self.ownerAuthorizer = ownerAuthorizer
        self.secretStore = secretStore
        self.companionStore = FileCompanionConfigurationStore(
            root: metadataRoot,
            trustedAnchor: companionTrustedAnchor
        )
        self.companionCloud = companionCloud
        companionApprovalDefault = UserDefaults.standard.bool(
            forKey: "KeyCourier.store.companionApprovalDefault"
        )
    }

    func startMonitoring() {
        guard monitoringTask == nil else { return }
        monitoringTask = Task { [weak self] in
            await self?.monitor()
        }
    }

    func stopMonitoring() {
        monitoringTask?.cancel()
        monitoringTask = nil
    }

    func monitor() async {
        refresh()
        queueMissingCredentialPromptIfNeeded()
        await notifyForMissingCredentialIfNeeded()
        await processCompanion(force: true)
        while !Task.isCancelled {
            do {
                try await Task.sleep(for: .seconds(3))
            } catch {
                return
            }
            refresh()
            queueMissingCredentialPromptIfNeeded()
            await notifyForMissingCredentialIfNeeded()
            await processCompanion()
        }
    }

    private func notifyForMissingCredentialIfNeeded() async {
        guard let request = missingCredentialRequest,
              promptedMissingCredentialRequestIDs.contains(request.id),
              notifiedMissingCredentialRequestIDs.insert(request.id).inserted else { return }
        await notificationService.notifyIfNeeded(for: request.id)
    }

    func refresh() {
        companionConfiguration = (try? companionStore.configuration()) ?? CompanionConfiguration()
        guard let queue else {
            pairings = []
            trustedBridgeID = nil
            pendingRequestCount = 0
            pendingRequests = []
            statusMessage = "Pairing is available only in a signed App Store build."
            return
        }

        do {
            let identity = try identityStore.loadOrCreate()
            self.identity = identity
            secrets = try metadataStore.secrets()
            let pinnedPeer = try peerStore.load()
            trustedBridgeID = pinnedPeer?.bridgeID
            var records: [StoreBridgePairing] = []
            let registrations = try queue.registrations()
            for registration in registrations {
                guard (try? BridgeCrypto.verify(registration)) != nil else { continue }
                guard let proposal = try? proposal(
                    for: registration,
                    identity: identity,
                    queue: queue
                ), let pairingCode = try? BridgeCrypto.pairingCode(
                    registration: registration,
                    proposal: proposal
                ) else {
                    continue
                }
                let trusted = isTrusted(
                    registration: registration,
                    proposal: proposal,
                    pinnedPeer: pinnedPeer,
                    queue: queue
                )
                records.append(StoreBridgePairing(
                    registration: registration,
                    proposal: proposal,
                    pairingCode: pairingCode,
                    isTrusted: trusted
                ))
            }
            pairings = records
            pendingRequests = try queue.pendingRequests().compactMap { request in
                guard let pinnedPeer,
                      (try? BridgeCrypto.verify(
                          request,
                          signingPublicKey: pinnedPeer.signingPublicKey,
                          expectedBridgeID: pinnedPeer.bridgeID
                      )) != nil else {
                    return nil
                }
                return StorePendingRequest(
                    signedRequest: request,
                    credentialName: secrets.first(where: {
                        $0.secretID == request.request.secretID
                    })?.displayName
                )
            }
            pendingRequestCount = pendingRequests.count
            try consumeReceipts(
                queue: queue,
                pinnedPeer: pinnedPeer,
                identity: identity
            )
            errorMessage = nil
            statusMessage = records.isEmpty
                ? (trustedBridgeID == nil
                    ? "Run keycourier-bridge pair to begin pairing."
                    : "Bridge trusted and ready for owner-approved delivery.")
                : "Compare the code with the bridge, then confirm trust."
        } catch {
            let nsError = error as NSError
            logger.error(
                "Bridge refresh failed type=\(String(reflecting: type(of: error)), privacy: .public) code=\(nsError.code, privacy: .public)"
            )
            pairings = []
            trustedBridgeID = nil
            pendingRequestCount = 0
            pendingRequests = []
            statusMessage = "Bridge setup needs attention."
            errorMessage = "The bridge pairing record could not be read."
        }
    }

    func presentMissingCredential(_ request: StorePendingRequest) {
        guard !secrets.contains(where: { $0.id == request.request.secretID }) else { return }
        promptedMissingCredentialRequestIDs.insert(request.id)
        missingCredentialRequest = request
    }

    func dismissMissingCredentialRequest() {
        if let request = missingCredentialRequest {
            promptedMissingCredentialRequestIDs.insert(request.id)
        }
        missingCredentialRequest = nil
    }

    private func queueMissingCredentialPromptIfNeeded() {
        if let request = missingCredentialRequest,
           pendingRequests.contains(where: { $0.id == request.id }),
           !secrets.contains(where: { $0.id == request.request.secretID }) {
            return
        }
        missingCredentialRequest = nil
        guard let request = pendingRequests.first(where: { pending in
            !secrets.contains(where: { secret in secret.id == pending.request.secretID })
        }) else { return }
        guard !promptedMissingCredentialRequestIDs.contains(request.id) else { return }
        promptedMissingCredentialRequestIDs.insert(request.id)
        missingCredentialRequest = request
    }

    func trust(_ pairing: StoreBridgePairing, confirmedPairingCode: String?) async {
        guard !isTrustingBridge else { return }
        guard confirmedPairingCode == pairing.pairingCode else {
            errorMessage = "Confirm that the pairing codes match before trusting this bridge."
            return
        }
        guard let queue, let identity else {
            refresh()
            return
        }
        isTrustingBridge = true
        defer { isTrustingBridge = false }

        do {
            guard let canonicalRegistration = try queue.registration(
                for: pairing.registration.bridgeID
            ), let canonicalProposal = try queue.proposal(
                for: pairing.registration.bridgeID
            ), canonicalRegistration == pairing.registration,
               canonicalProposal == pairing.proposal else {
                throw BridgeProtocolError.invalidRecord
            }
            let ownSigningPublicKey = try Curve25519.Signing.PrivateKey(
                rawRepresentation: identity.keys.signingPrivateKey
            ).publicKey.rawRepresentation
            guard pairing.proposal.appSigningPublicKey == ownSigningPublicKey else {
                throw BridgeProtocolError.invalidRecord
            }
            try await ownerAuthorizer.authorize(
                reason: "Trust this KeyCourier bridge on this Mac"
            )
            let registration = pairing.registration
            try BridgeCrypto.verify(registration)
            try BridgeCrypto.verify(pairing.proposal)
            guard try BridgeCrypto.pairingCode(
                registration: registration,
                proposal: pairing.proposal
            ) == confirmedPairingCode else {
                throw BridgeProtocolError.invalidRecord
            }
            let registrationDigest = try registration.digest()
            guard pairing.proposal.bridgeID == registration.bridgeID,
                  pairing.proposal.registrationDigest == registrationDigest else {
                throw BridgeProtocolError.invalidRecord
            }
            let expectedPeer = try BridgePinnedPeer(
                bridgeID: registration.bridgeID,
                signingPublicKey: registration.signingPublicKey,
                keyAgreementPublicKey: registration.keyAgreementPublicKey,
                registrationDigest: registrationDigest
            )
            if let pinnedPeer = try peerStore.load(), pinnedPeer != expectedPeer {
                throw BridgeStorageError.invalidIdentity
            }
            try peerStore.save(expectedPeer)
            do {
                let grant = try BridgeCrypto.trustGrant(
                    for: registration,
                    proposal: pairing.proposal,
                    appSigningPrivateKey: identity.keys.signingPrivateKey
                )
                _ = try queue.save(grant)
            } catch {
                try? peerStore.delete()
                throw error
            }
            statusMessage = "Bridge trusted. Run keycourier-bridge pair again to finish the handshake."
            refresh()
        } catch is CancellationError {
            return
        } catch {
            errorMessage = "Trust was not saved. Compare the pairing code and try again."
        }
    }

    func approve(_ pending: StorePendingRequest) async {
        guard !processingRequestIDs.contains(pending.id),
              let queue,
              let identity,
              let pinnedBridge = try? peerStore.load() else { return }
        processingRequestIDs.insert(pending.id)
        defer { processingRequestIDs.remove(pending.id) }
        do {
            _ = try await BridgeApprovalDispatcher(
                secretStore: secretStore,
                ownerAuthorizer: ownerAuthorizer
            ).approve(
                pending.signedRequest,
                pinnedBridge: pinnedBridge,
                storeIdentity: identity,
                secrets: secrets,
                queue: queue
            )
            statusMessage = "Credential approved and encrypted for the bridge."
            wakeBridge()
            refresh()
        } catch is CancellationError {
            return
        } catch {
            errorMessage = "Approval was not completed. Check the credential and try again."
        }
    }

    func deny(_ pending: StorePendingRequest) {
        guard !processingRequestIDs.contains(pending.id),
              let queue,
              let identity,
              let pinnedBridge = try? peerStore.load() else { return }
        processingRequestIDs.insert(pending.id)
        defer { processingRequestIDs.remove(pending.id) }
        do {
            _ = try BridgeApprovalDispatcher(
                secretStore: secretStore,
                ownerAuthorizer: ownerAuthorizer
            ).deny(
                pending.signedRequest,
                pinnedBridge: pinnedBridge,
                storeIdentity: identity,
                queue: queue
            )
            statusMessage = "Request denied."
            wakeBridge()
            refresh()
        } catch {
            errorMessage = "The request could not be denied safely."
        }
    }

    func saveCredential(
        name: String,
        material: CompanionCredentialMaterial,
        materialKind: SecretMaterialKind,
        allowsCompanionApproval: Bool
    ) async -> Bool {
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let companionApproval = allowsCompanionApproval && companionConfiguration.isEnabled
        do {
            let secretID = try await uniqueSecretID(for: trimmedName.isEmpty ? "credential" : trimmedName)
            let displayName = trimmedName.isEmpty
                ? generatedCredentialName(for: secretID)
                : trimmedName
            let value = try material.deliveryData()
            try await secretStore.save(
                value,
                id: secretID,
                allowsRemoteApproval: companionApproval
            )
            do {
                try metadataStore.save(SecretMetadata(
                    secretID: secretID,
                    displayName: displayName,
                    kind: materialKind == .usernamePassword ? .password : .apiKey,
                    materialKind: materialKind,
                    allowsCompanionApproval: companionApproval
                ))
            } catch {
                try? await secretStore.delete(
                    id: secretID,
                    reason: "Roll back an incomplete KeyCourier credential"
                )
                throw error
            }
            refresh()
            return true
        } catch let error as StoreCredentialStorageError {
            errorMessage = error.localizedDescription
            return false
        } catch is CancellationError {
            return false
        } catch {
            errorMessage = "The credential could not be saved."
            return false
        }
    }

    func saveRequestedCredential(
        name: String,
        pending: StorePendingRequest,
        material: CompanionCredentialMaterial,
        materialKind: SecretMaterialKind,
        allowsCompanionApproval: Bool
    ) async -> Bool {
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard pendingRequests.contains(where: { $0.id == pending.id }),
              !secrets.contains(where: { $0.id == pending.request.secretID }) else {
            errorMessage = "That request is no longer waiting for a credential."
            return false
        }
        let companionApproval = allowsCompanionApproval && companionConfiguration.isEnabled

        do {
            let value = try material.deliveryData()
            let displayName = trimmedName.isEmpty
                ? (pending.suggestedCredentialName.isEmpty
                    ? generatedCredentialName(for: pending.request.secretID)
                    : pending.suggestedCredentialName)
                : trimmedName
            let metadata = SecretMetadata(
                secretID: pending.request.secretID,
                displayName: displayName,
                kind: materialKind == .usernamePassword
                    ? .password
                    : requestedSecretKind(pending.request),
                materialKind: materialKind,
                allowsCompanionApproval: companionApproval
            )
            guard try await !secretStore.contains(id: metadata.id) else {
                throw StoreCredentialStorageError.migrationRequired
            }
            try await secretStore.save(
                value,
                id: metadata.id,
                allowsRemoteApproval: companionApproval
            )
            do {
                try metadataStore.save(metadata)
            } catch {
                try? await secretStore.delete(
                    id: metadata.id,
                    reason: "Roll back an incomplete KeyCourier credential"
                )
                throw error
            }
            missingCredentialRequest = nil
            refresh()
            await processCompanion(force: true)
            return true
        } catch let error as StoreCredentialStorageError {
            errorMessage = error.localizedDescription
            return false
        } catch is CancellationError {
            return false
        } catch {
            errorMessage = "The credential could not be saved."
            return false
        }
    }

    func replaceCredential(
        _ metadata: SecretMetadata,
        material: CompanionCredentialMaterial,
        materialKind: SecretMaterialKind,
        allowsCompanionApproval: Bool
    ) async -> Bool {
        guard let existing = secrets.first(where: { $0.id == metadata.id }) else {
            errorMessage = "That credential could not be found."
            return false
        }
        guard !allowsCompanionApproval || companionConfiguration.isEnabled else {
            errorMessage = "Enable the iPhone companion before allowing remote approval."
            return false
        }

        do {
            let value = try material.deliveryData()
            if existing.allowsCompanionApproval != allowsCompanionApproval {
                try await ownerAuthorizer.authorize(
                    reason: "Change iPhone approval for " + existing.displayName
                )
            }
            guard let previousValue = try await secretStore.read(
                id: existing.id,
                reason: "Replace " + existing.displayName + " in KeyCourier"
            ) else {
                throw KeyCourierError.invalidMetadata
            }
            var updated = existing
            updated.kind = materialKind == .usernamePassword ? .password : existing.kind
            updated.materialKind = materialKind
            updated.allowsCompanionApproval = allowsCompanionApproval
            updated.updatedAt = Date()
            do {
                try await secretStore.save(
                    value,
                    id: updated.id,
                    allowsRemoteApproval: allowsCompanionApproval
                )
                try metadataStore.save(updated)
            } catch {
                try? await secretStore.save(
                    previousValue,
                    id: existing.id,
                    allowsRemoteApproval: existing.allowsTelegramApproval
                        || existing.allowsCompanionApproval
                )
                throw error
            }
            refresh()
            return true
        } catch is CancellationError {
            return false
        } catch {
            errorMessage = "The credential could not be replaced."
            return false
        }
    }

    func deleteCredential(_ metadata: SecretMetadata) async {
        do {
            try await ownerAuthorizer.authorize(reason: "Delete \(metadata.displayName) from KeyCourier")
            guard let previousValue = try await secretStore.read(
                id: metadata.id,
                reason: "Delete \(metadata.displayName) from KeyCourier"
            ) else {
                throw KeyCourierError.invalidMetadata
            }
            try metadataStore.removeSecret(id: metadata.secretID)
            do {
                try await secretStore.delete(
                    id: metadata.secretID,
                    reason: "Delete \(metadata.displayName) from KeyCourier"
                )
            } catch {
                try? metadataStore.save(metadata)
                try? await secretStore.save(
                    previousValue,
                    id: metadata.id,
                    allowsRemoteApproval: metadata.allowsTelegramApproval
                        || metadata.allowsCompanionApproval
                )
                throw error
            }
            refresh()
        } catch is CancellationError {
            return
        } catch {
            errorMessage = "The credential was not deleted."
        }
    }

    func unpairBridge() async {
        guard let queue else { return }
        do {
            try await ownerAuthorizer.authorize(reason: "Unpair KeyCourier Bridge")
            let identity = try identityStore.loadOrCreate()
            let pinnedPeer = try peerStore.load()
            let revocation = try pinnedPeer.map { peer in
                try BridgeCrypto.trustRevocation(
                    bridgeID: peer.bridgeID,
                    registrationDigest: peer.registrationDigest,
                    appSigningPrivateKey: identity.keys.signingPrivateKey
                )
            }
            try queue.purgeAll()
            if let revocation {
                _ = try queue.save(revocation)
            }
            try peerStore.delete()
            trustedBridgeID = nil
            refresh()
            statusMessage = "Bridge unpaired. Revocation is ready for KeyCourier Bridge."
            wakeBridge(
                fallbackMessage: "Bridge unpaired locally. Open KeyCourier Bridge to complete revocation."
            )
        } catch is CancellationError {
            return
        } catch {
            errorMessage = "Unpair did not complete. Bridge trust may remain and some queue records may already be removed. Resolve queue health, then try again."
        }
    }

    func setCompanionEnabled(_ isEnabled: Bool) async {
        do {
            if isEnabled {
                _ = try companionKeyStore.loadOrCreate()
                try await companionCloud.requireAvailableAccount()
            } else {
                try await companionCloud.purgeTransientData()
                try await companionCloud.replaceCredentialSummaries([])
                try await companionCloud.replaceRequests([])
                companionRegistrations = []
                companionPairingCode = nil
            }
            companionConfiguration = try companionStore.setEnabled(isEnabled)
            companionStatusMessage = isEnabled
                ? "iPhone pairing is ready. Open KeyCourier on your iPhone to register it."
                : "iPhone companion is off."
            companionLastRefresh = .distantPast
            if isEnabled {
                await processCompanion(force: true)
            }
        } catch is CancellationError {
            return
        } catch {
            errorMessage = "iPhone companion setup could not be changed. Check that iCloud is available."
        }
    }

    func setCompanionApprovalDefault(_ isEnabled: Bool) {
        companionApprovalDefault = isEnabled
        UserDefaults.standard.set(
            isEnabled,
            forKey: "KeyCourier.store.companionApprovalDefault"
        )
    }

    func approveCompanionRegistration(_ registration: CompanionDeviceRegistration) async {
        guard companionConfiguration.trustedDevice == nil
                || companionConfiguration.trustedDevice?.id == registration.id else {
            errorMessage = "Remove the currently paired iPhone before approving another one."
            return
        }
        do {
            try await ownerAuthorizer.authorize(reason: "Pair this iPhone with KeyCourier")
            let accountIdentifier = try await companionCloud.accountIdentifier()
            let identity = try companionKeyStore.loadOrCreate()
            let macRegistration = try CompanionCrypto.registration(
                deviceID: identity.id,
                deviceName: Host.current().localizedName ?? "KeyCourier Mac",
                keys: identity.keys
            )
            var approvedRegistration = registration
            approvedRegistration.status = .approved
            approvedRegistration.macKeyAgreementPublicKey = macRegistration.keyAgreementPublicKey
            approvedRegistration.macSigningPublicKey = macRegistration.signingPublicKey
            do {
                companionConfiguration = try companionStore.trust(
                    approvedRegistration,
                    accountIdentifier: accountIdentifier
                )
            } catch {
                // A failed local write must never be followed by a remote
                // approval. If the write was partially committed, clear the
                // uncertain local trust before the next retry.
                if (try? companionStore.configuration())?.trustedDevice?.id == registration.id {
                    companionConfiguration = (try? companionStore.requireRePair())
                        ?? CompanionConfiguration()
                }
                throw error
            }
            do {
                try await companionCloud.purgeTransientData()
                try await companionCloud.updateDeviceRegistration(
                    id: registration.id,
                    status: .approved,
                    macKeyAgreementPublicKey: macRegistration.keyAgreementPublicKey,
                    macSigningPublicKey: macRegistration.signingPublicKey
                )
                companionPairingCode = try CompanionCrypto.pairingCode(for: approvedRegistration)
                companionRegistrations.removeAll { $0.id == registration.id }
                companionStatusMessage = registration.deviceName + " is paired."
            } catch {
                // Local trust is established first. If the remote commit is
                // unavailable or uncertain, revoke the remote registration
                // best-effort and clear local trust before retrying.
                try? await companionCloud.updateDeviceRegistration(
                    id: registration.id,
                    status: .denied,
                    macKeyAgreementPublicKey: nil,
                    macSigningPublicKey: nil
                )
                companionConfiguration = (try? companionStore.requireRePair())
                    ?? CompanionConfiguration()
                companionPairingCode = nil
                throw error
            }
        } catch is CancellationError {
            return
        } catch {
            errorMessage = "The iPhone could not be paired. Try again after checking iCloud."
        }
    }

    func declineCompanionRegistration(_ registration: CompanionDeviceRegistration) async {
        do {
            try await companionCloud.updateDeviceRegistration(
                id: registration.id,
                status: .denied,
                macKeyAgreementPublicKey: nil,
                macSigningPublicKey: nil
            )
            companionRegistrations.removeAll { $0.id == registration.id }
        } catch {
            errorMessage = "The iPhone registration could not be declined."
        }
    }

    func removeTrustedCompanion() async {
        guard let trusted = companionConfiguration.trustedDevice else { return }
        do {
            try await ownerAuthorizer.authorize(reason: "Remove the paired KeyCourier iPhone")
            let accountIdentifier = try await companionCloud.accountIdentifier()
            guard companionConfiguration.isBound(to: accountIdentifier) else {
                companionConfiguration = try companionStore.requireRePair()
                companionRegistrations = []
                companionPairingCode = nil
                companionStatusMessage = "Pairing was reset. Register this iPhone again."
                return
            }
            try await companionCloud.updateDeviceRegistration(
                id: trusted.id,
                status: .denied,
                macKeyAgreementPublicKey: nil,
                macSigningPublicKey: nil
            )
            try await companionCloud.purgeTransientData()
            try await companionCloud.replaceCredentialSummaries([])
            try await companionCloud.replaceRequests([])
            companionConfiguration = try companionStore.removeTrustedDevice()
            companionPairingCode = nil
            companionStatusMessage = "The iPhone was removed. Its future approvals will be rejected."
        } catch is CancellationError {
            return
        } catch {
            errorMessage = "The paired iPhone could not be removed safely."
        }
    }

    func processCompanion(force: Bool = false) async {
        guard companionConfiguration.isEnabled,
              force || Date().timeIntervalSince(companionLastRefresh) >= 10,
              !isProcessingCompanion else { return }
        isProcessingCompanion = true
        defer { isProcessingCompanion = false }
        companionLastRefresh = Date()

        do {
            let accountIdentifier = try await companionCloud.accountIdentifier()
            if companionConfiguration.trustedDevice != nil,
               !companionConfiguration.isBound(to: accountIdentifier) {
                companionConfiguration = try companionStore.requireRePair()
                companionRegistrations = []
                companionPairingCode = nil
                companionStatusMessage = "The iCloud account changed. Pair this iPhone again."
                return
            }
            let identity = try companionKeyStore.loadOrCreate()
            let registrations = try await companionCloud.deviceRegistrations()
            companionRegistrations = registrations.filter {
                $0.status == .pending && $0.id != companionConfiguration.trustedDevice?.id
            }

            guard let trusted = companionConfiguration.trustedDevice else {
                companionPairingCode = nil
                companionStatusMessage = companionRegistrations.isEmpty
                    ? "Waiting for an iPhone registration."
                    : "Review the iPhone registration below."
                return
            }

            let macRegistration = try CompanionCrypto.registration(
                deviceID: identity.id,
                deviceName: Host.current().localizedName ?? "KeyCourier Mac",
                keys: identity.keys
            )
            var codeRegistration = trusted.registration
            codeRegistration.status = .approved
            codeRegistration.macKeyAgreementPublicKey = macRegistration.keyAgreementPublicKey
            codeRegistration.macSigningPublicKey = macRegistration.signingPublicKey
            companionPairingCode = try CompanionCrypto.pairingCode(for: codeRegistration)

            guard let remoteRegistration = registrations.first(where: { $0.id == trusted.id }),
                  remoteRegistration.status == .approved,
                  remoteRegistration.signingPublicKey == trusted.registration.signingPublicKey,
                  remoteRegistration.keyAgreementPublicKey == trusted.registration.keyAgreementPublicKey,
                  remoteRegistration.macKeyAgreementPublicKey == macRegistration.keyAgreementPublicKey,
                  remoteRegistration.macSigningPublicKey == macRegistration.signingPublicKey else {
                companionConfiguration = try companionStore.requireRePair()
                companionRegistrations = registrations.filter {
                    $0.status == .pending && $0.id != trusted.id
                }
                companionPairingCode = nil
                companionStatusMessage = "The iPhone pairing record changed. Pair this iPhone again."
                return
            }

            let summaries = try pendingRequests.compactMap { pending -> CompanionRequestSummary? in
                guard let metadata = secrets.first(where: { $0.id == pending.request.secretID }),
                      metadata.allowsCompanionApproval else { return nil }
                let summary = try CompanionRequestSummary(
                    requestID: pending.id,
                    clientName: pending.request.client.rawValue.capitalized,
                    credentialName: metadata.displayName,
                    destinationName: pending.request.consumerID.rawValue
                        + " → "
                        + pending.request.targetID.rawValue,
                    reason: pending.request.reason,
                    createdAt: pending.request.createdAt,
                    expiresAt: pending.request.expiresAt
                )
                return try CompanionCrypto.sign(summary, keys: identity.keys)
            }
            let credentialSummaries = try secrets.filter(\.allowsCompanionApproval).map {
                try CompanionCredentialSummary(
                    secretID: $0.id.rawValue,
                    displayName: $0.displayName,
                    kind: $0.kind.rawValue,
                    materialKind: companionMaterialKind(for: $0.materialKind)
                )
            }
            try await companionCloud.replaceCredentialSummaries(credentialSummaries)
            try await companionCloud.replaceRequests(summaries)
            try await processCompanionDecisions(trusted: trusted, summaries: summaries)
            try await processCompanionSecretEnvelopes(trusted: trusted, identity: identity)
            companionStatusMessage = summaries.isEmpty
                ? "iPhone is connected. No approval requests are waiting."
                : "iPhone is connected with " + String(summaries.count)
                    + " approval request(s) waiting."
        } catch is CancellationError {
            return
        } catch {
            companionStatusMessage = "iPhone companion could not reach iCloud. It will retry safely."
        }
    }

    private func processCompanionDecisions(
        trusted: TrustedCompanionDevice,
        summaries: [CompanionRequestSummary]
    ) async throws {
        let summariesByID = Dictionary(uniqueKeysWithValues: summaries.map { ($0.id, $0) })
        for decision in try await companionCloud.decisions() {
            if companionConfiguration.processedDecisionIDs.contains(decision.id) {
                try? await companionCloud.deleteDecision(id: decision.id)
                continue
            }

            let pending: StorePendingRequest
            do {
                pending = try validateCompanionDecision(
                    decision,
                    trusted: trusted,
                    summariesByID: summariesByID
                )
            } catch {
                companionStatusMessage = "An invalid or expired iPhone decision was rejected."
                companionConfiguration = try companionStore.markDecisionProcessed(decision.id)
                try? await companionCloud.deleteDecision(id: decision.id)
                continue
            }

            do {
                if decision.action == .approve {
                    try await approveFromCompanion(pending)
                } else {
                    try denyFromCompanion(pending)
                }
            } catch {
                companionStatusMessage = "The iPhone decision could not be applied yet. KeyCourier will retry safely."
                continue
            }

            companionConfiguration = try companionStore.markDecisionProcessed(decision.id)
            try? await companionCloud.deleteDecision(id: decision.id)
            try? await companionCloud.deleteRequest(id: decision.requestID)
        }
    }

    private func validateCompanionDecision(
        _ decision: CompanionDecision,
        trusted: TrustedCompanionDevice,
        summariesByID: [UUID: CompanionRequestSummary]
    ) throws -> StorePendingRequest {
        guard decision.deviceID == trusted.id else {
            throw CompanionProtocolError.invalidSignature
        }
        try CompanionCrypto.verify(
            decision,
            signingPublicKey: trusted.registration.signingPublicKey
        )
        guard let summary = summariesByID[decision.requestID],
              decision.requestDigest == (try summary.digest()),
              let pending = pendingRequests.first(where: { $0.id == decision.requestID }),
              secrets.first(where: { $0.id == pending.request.secretID })?.allowsCompanionApproval == true else {
            throw CompanionProtocolError.invalidSignature
        }
        return pending
    }

    private func approveFromCompanion(_ pending: StorePendingRequest) async throws {
        guard !processingRequestIDs.contains(pending.id),
              let queue,
              let identity,
              let pinnedBridge = try peerStore.load() else {
            throw BridgeProtocolError.invalidRecord
        }
        processingRequestIDs.insert(pending.id)
        defer { processingRequestIDs.remove(pending.id) }
        _ = try await BridgeApprovalDispatcher(
            secretStore: secretStore,
            ownerAuthorizer: ownerAuthorizer
        ).approveFromCompanion(
            pending.signedRequest,
            pinnedBridge: pinnedBridge,
            storeIdentity: identity,
            secrets: secrets,
            queue: queue
        )
        statusMessage = "Credential approved on iPhone and encrypted for the bridge."
        wakeBridge()
        refresh()
    }

    private func denyFromCompanion(_ pending: StorePendingRequest) throws {
        guard !processingRequestIDs.contains(pending.id),
              let queue,
              let identity,
              let pinnedBridge = try peerStore.load() else {
            throw BridgeProtocolError.invalidRecord
        }
        processingRequestIDs.insert(pending.id)
        defer { processingRequestIDs.remove(pending.id) }
        _ = try BridgeApprovalDispatcher(
            secretStore: secretStore,
            ownerAuthorizer: ownerAuthorizer
        ).deny(
            pending.signedRequest,
            pinnedBridge: pinnedBridge,
            storeIdentity: identity,
            queue: queue
        )
        statusMessage = "Request denied on iPhone."
        wakeBridge()
        refresh()
    }

    private func processCompanionSecretEnvelopes(
        trusted: TrustedCompanionDevice,
        identity: CompanionDeviceIdentity
    ) async throws {
        for envelope in try await companionCloud.secretEnvelopes() {
            if companionConfiguration.processedEnvelopeIDs.contains(envelope.id) {
                try? await companionCloud.deleteSecretEnvelope(id: envelope.id)
                continue
            }

            var consumeEnvelope = false
            do {
                guard envelope.deviceID == trusted.id else {
                    throw CompanionProtocolError.invalidSignature
                }
                let payload = try CompanionCrypto.open(
                    envelope,
                    recipientKeys: identity.keys,
                    senderSigningPublicKey: trusted.registration.signingPublicKey
                )
                try await importCompanionSecret(payload)
                consumeEnvelope = true
            } catch {
                consumeEnvelope = shouldConsumeCompanionEnvelope(after: error)
                if let storageError = error as? StoreCredentialStorageError {
                    companionStatusMessage = storageError.localizedDescription
                } else {
                    companionStatusMessage = consumeEnvelope
                        ? "An invalid iPhone credential was rejected."
                        : "The iPhone credential could not be saved yet. KeyCourier will retry safely."
                }
            }
            guard consumeEnvelope else { continue }
            companionConfiguration = try companionStore.markEnvelopeProcessed(envelope.id)
            try? await companionCloud.deleteSecretEnvelope(id: envelope.id)
        }
    }

    private func shouldConsumeCompanionEnvelope(after error: Error) -> Bool {
        switch error {
        case CompanionProtocolError.invalidRecord,
             CompanionProtocolError.invalidSignature,
             CompanionProtocolError.expired,
             CompanionProtocolError.decryptionFailed,
             KeyCourierError.invalidIdentifier,
             KeyCourierError.invalidMetadata,
             KeyCourierError.malformedSecretValue:
            return true
        default:
            return false
        }
    }

    private func importCompanionSecret(_ payload: CompanionSecretPayload) async throws {
        let secretID = try SecretID(validating: payload.secretID)
        let value = try payload.deliveryData()
        if payload.replacesExisting {
            guard let existing = secrets.first(where: { $0.id == secretID }),
                  existing.allowsCompanionApproval else {
                throw KeyCourierError.invalidMetadata
            }
            var updated = existing
            updated.kind = materialKind(for: payload.material, existing: existing.kind)
            updated.materialKind = secretMaterialKind(for: payload.material)
            updated.updatedAt = Date()
            guard let previousValue = try await secretStore.read(
                id: existing.id,
                reason: "Replace " + existing.displayName + " from iPhone"
            ) else {
                throw KeyCourierError.invalidMetadata
            }
            try await secretStore.save(
                value,
                id: secretID,
                allowsRemoteApproval: true
            )
            do {
                try metadataStore.save(updated)
            } catch {
                try? await secretStore.save(
                    previousValue,
                    id: existing.id,
                    allowsRemoteApproval: existing.allowsTelegramApproval
                        || existing.allowsCompanionApproval
                )
                throw error
            }
            refresh()
            return
        }

        guard !GuidedDestination.allCases.contains(where: { $0.secretIDValue == secretID.rawValue }),
              !secrets.contains(where: { $0.id == secretID }) else {
            throw KeyCourierError.invalidMetadata
        }
        guard try await !secretStore.contains(id: secretID) else {
            throw StoreCredentialStorageError.migrationRequired
        }
        guard let kind = SecretKind(rawValue: payload.kind) else {
            throw KeyCourierError.invalidMetadata
        }
        let metadata = SecretMetadata(
            secretID: secretID,
            displayName: payload.displayName,
            kind: kind,
            materialKind: secretMaterialKind(for: payload.material),
            ownerName: payload.ownerName,
            projectName: payload.projectName,
            environmentName: payload.environmentName,
            rotationDueAt: payload.rotationDueAt,
            expiresAt: payload.expiresAt,
            allowsCompanionApproval: true
        )
        try await secretStore.save(value, id: secretID, allowsRemoteApproval: true)
        do {
            try metadataStore.save(metadata)
        } catch {
            try? await secretStore.delete(
                id: secretID,
                reason: "Roll back an incomplete iPhone credential"
            )
            throw error
        }
        refresh()
    }

    private func companionMaterialKind(
        for materialKind: SecretMaterialKind
    ) -> CompanionCredentialMaterialKind {
        switch materialKind {
        case .single: .single
        case .usernamePassword: .usernamePassword
        }
    }

    private func secretMaterialKind(
        for material: CompanionCredentialMaterial
    ) -> SecretMaterialKind {
        switch material {
        case .single: .single
        case .usernamePassword: .usernamePassword
        }
    }

    private func materialKind(
        for material: CompanionCredentialMaterial,
        existing: SecretKind
    ) -> SecretKind {
        switch material {
        case .single:
            existing
        case .usernamePassword:
            .password
        }
    }

    private func consumeReceipts(
        queue: BridgeQueue,
        pinnedPeer: BridgePinnedPeer?,
        identity: BridgeIdentity
    ) throws {
        guard let pinnedPeer else { return }
        let storeSigningPublicKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: identity.keys.signingPrivateKey
        ).publicKey.rawRepresentation
        for receipt in try queue.receipts() {
            guard let command = try queue.command(for: receipt.commandID, at: receipt.receipt.recordedAt) else {
                continue
            }
            try BridgeCrypto.verify(
                command,
                appSigningPublicKey: storeSigningPublicKey,
                expectedBridgeID: pinnedPeer.bridgeID,
                expectedRequestDigest: receipt.requestDigest,
                at: command.createdAt
            )
            try BridgeCrypto.verify(
                receipt,
                signingPublicKey: pinnedPeer.signingPublicKey,
                expectedBridgeID: pinnedPeer.bridgeID,
                expectedCommandID: command.commandID,
                expectedRequestID: command.requestID,
                expectedRequestDigest: command.requestDigest
            )
            guard receipt.receipt.targetID == command.targetID,
                  receipt.receipt.consumerID == command.consumerID else {
                throw BridgeProtocolError.invalidRecord
            }
            _ = try receiptStore.record(receipt.receipt)
            try queue.removeRequest(command.requestID)
            try queue.removeCommand(command.commandID)
            try queue.removeReceipt(command.commandID)
        }
    }

    private func uniqueSecretID(for name: String) async throws -> SecretID {
        let slug = name.lowercased().unicodeScalars.map { scalar -> Character in
            CharacterSet.alphanumerics.contains(scalar) ? Character(String(scalar)) : "-"
        }
        let base = String(slug)
            .split(separator: "-", omittingEmptySubsequences: true)
            .joined(separator: "-")
            .prefix(48)
        let candidate = base.isEmpty ? "credential" : String(base)
        let existing = Set(secrets.map(\.secretID.rawValue))
        if !existing.contains(candidate) {
            let id = try SecretID(validating: candidate)
            guard try await !secretStore.contains(id: id) else {
                throw StoreCredentialStorageError.migrationRequired
            }
            return id
        }
        for _ in 0..<8 {
            let id = try SecretID(
                validating: "\(candidate)-\(UUID().uuidString.lowercased().prefix(8))"
            )
            guard !existing.contains(id.rawValue), try await !secretStore.contains(id: id) else {
                continue
            }
            return id
        }
        throw KeyCourierError.invalidIdentifier
    }

    private func generatedCredentialName(for secretID: SecretID) -> String {
        "Credential \(secretID.rawValue.suffix(6).uppercased())"
    }

    private func requestedSecretKind(_ request: SecretRequest) -> SecretKind {
        let id = request.secretID.rawValue
        return id.contains("password") || id.contains("passwd") ? .password : .apiKey
    }

    private func wakeBridge(
        fallbackMessage: String = "Approved. Open KeyCourier Bridge to complete delivery."
    ) {
        guard let url = NSWorkspace.shared.urlForApplication(
            withBundleIdentifier: "com.drewsdigest.KeyCourierBridge"
        ) else {
            statusMessage = fallbackMessage
            return
        }
        NSWorkspace.shared.openApplication(
            at: url,
            configuration: NSWorkspace.OpenConfiguration()
        ) { _, error in
            if error != nil {
                Task { @MainActor in
                    self.statusMessage = fallbackMessage
                }
            }
        }
    }

    private func proposal(
        for registration: BridgeRegistration,
        identity: BridgeIdentity,
        queue: BridgeQueue
    ) throws -> BridgePairingProposal {
        let ownSigningPublicKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: identity.keys.signingPrivateKey
        ).publicKey.rawRepresentation
        if let existing = try? queue.proposal(for: registration.bridgeID),
           existing.registrationDigest == (try registration.digest()),
           existing.appSigningPublicKey == ownSigningPublicKey,
           (try? BridgeCrypto.verify(existing)) != nil {
            return existing
        }
        try? queue.removeProposal(for: registration.bridgeID)
        let proposal = try BridgeCrypto.pairingProposal(
            for: registration,
            appSigningPrivateKey: identity.keys.signingPrivateKey
        )
        let signed = try BridgeCrypto.sign(
            proposal,
            privateKey: identity.keys.signingPrivateKey
        )
        _ = try queue.save(signed)
        return signed
    }

    private func isTrusted(
        registration: BridgeRegistration,
        proposal: BridgePairingProposal,
        pinnedPeer: BridgePinnedPeer?,
        queue: BridgeQueue
    ) -> Bool {
        guard let pinnedPeer,
              pinnedPeer.bridgeID == registration.bridgeID,
              pinnedPeer.signingPublicKey == registration.signingPublicKey,
              pinnedPeer.keyAgreementPublicKey == registration.keyAgreementPublicKey,
              let registrationDigest = try? registration.digest(),
              pinnedPeer.registrationDigest == registrationDigest,
              let grant = try? queue.grant(for: registration.bridgeID),
              (try? BridgeCrypto.verify(
                  grant,
                  appSigningPublicKey: proposal.appSigningPublicKey
              )) != nil,
              grant.registrationDigest == registrationDigest,
              let proposalDigest = try? proposal.digest(),
              grant.proposalDigest == proposalDigest else {
            return false
        }
        return true
    }
}

private struct StoreBridgePairing: Identifiable, Sendable {
    let registration: BridgeRegistration
    let proposal: BridgePairingProposal
    let pairingCode: String
    let isTrusted: Bool

    var id: UUID { registration.bridgeID }

    init(
        registration: BridgeRegistration,
        proposal: BridgePairingProposal,
        pairingCode: String,
        isTrusted: Bool
    ) {
        self.registration = registration
        self.proposal = proposal
        self.pairingCode = pairingCode
        self.isTrusted = isTrusted
    }
}

private struct StorePendingRequest: Identifiable, Sendable {
    let signedRequest: SignedBridgeRequest
    let credentialName: String?
    var id: UUID { signedRequest.id }
    var request: SecretRequest { signedRequest.request }

    var suggestedCredentialName: String {
        if let credentialName, !credentialName.isEmpty { return credentialName }
        return request.secretID.rawValue
            .split(whereSeparator: { $0 == "-" || $0 == "_" || $0 == "." })
            .map { $0.capitalized }
            .joined(separator: " ")
    }
}

private struct StoreRootView: View {
    let model: StoreBridgeModel
    @Environment(\.openWindow) private var openWindow
    @State private var showingAddCredential = false

    var body: some View {
        TabView {
            StoreCredentialsView(model: model, showingAddCredential: $showingAddCredential)
                .tabItem { Label("Credentials", systemImage: "key.fill") }
            StoreRequestsView(model: model)
                .tabItem { Label("Requests", systemImage: "checkmark.shield") }
                .badge(model.pendingRequestCount)
            StoreStatusView(model: model)
                .tabItem { Label("Bridge", systemImage: "link") }
            StoreCompanionView(model: model)
                .tabItem { Label("iPhone", systemImage: "iphone.gen3") }
        }
        .sheet(isPresented: $showingAddCredential) {
            StoreCredentialEntryView(model: model)
        }
        .sheet(
            isPresented: Binding(
                get: { model.missingCredentialRequest != nil },
                set: { if !$0 { model.dismissMissingCredentialRequest() } }
            )
        ) {
            if let request = model.missingCredentialRequest {
                StoreRequestedCredentialEntryView(model: model, request: request)
            }
        }
        .onChange(of: model.missingCredentialRequest?.id, initial: true) { _, requestID in
            guard requestID != nil else { return }
            NSApplication.shared.activate(ignoringOtherApps: true)
            openWindow(id: "main")
        }
    }
}

private struct StoreCredentialsView: View {
    let model: StoreBridgeModel
    @Binding var showingAddCredential: Bool
    @State private var editingCredential: SecretMetadata?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Credentials")
                        .font(.title2.weight(.semibold))
                    Text("Add only the key, password or login. KeyCourier keeps it in your Mac Keychain.")
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Add credential", systemImage: "plus") {
                    showingAddCredential = true
                }
                .buttonStyle(.borderedProminent)
            }

            if model.secrets.isEmpty {
                ContentUnavailableView(
                    "No credentials yet",
                    systemImage: "key",
                    description: Text("Add a credential, then an LLM can request it by name without seeing its value.")
                )
            } else {
                List(model.secrets) { secret in
                    HStack(spacing: 12) {
                        Image(systemName: secret.materialKind == .usernamePassword ? "person.badge.key.fill" : "key.fill")
                            .foregroundStyle(.tint)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(secret.displayName)
                                .font(.headline)
                            Text(secret.materialKind == .usernamePassword ? "Username and password" : "Key or password")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        VStack(alignment: .trailing, spacing: 4) {
                            Button("Replace", systemImage: "arrow.triangle.2.circlepath") {
                                editingCredential = secret
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                            Text(secret.secretID.rawValue)
                                .font(.caption.monospaced())
                                .foregroundStyle(.tertiary)
                        }
                    }
                    .padding(.vertical, 4)
                    .contextMenu {
                        Button("Replace value", systemImage: "arrow.triangle.2.circlepath") {
                            editingCredential = secret
                        }
                        Button("Delete", systemImage: "trash", role: .destructive) {
                            Task { await model.deleteCredential(secret) }
                        }
                    }
                }
                .listStyle(.inset)
            }

            if let error = model.errorMessage {
                Text(error).foregroundStyle(.red)
            }
        }
        .padding(24)
        .sheet(item: $editingCredential) { credential in
            StoreCredentialReplacementView(model: model, credential: credential)
        }
    }
}

private struct StoreRequestsView: View {
    let model: StoreBridgeModel

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Approval requests")
                    .font(.title2.weight(.semibold))
                Text("Review where the credential is going. Its value is never shown to the LLM.")
                    .foregroundStyle(.secondary)
            }

            if model.pendingRequests.isEmpty {
                ContentUnavailableView(
                    "You’re all caught up",
                    systemImage: "checkmark.shield",
                    description: Text("New authenticated requests from your paired Bridge appear here.")
                )
            } else {
                ScrollView {
                    LazyVStack(spacing: 12) {
                        ForEach(model.pendingRequests) { pending in
                            VStack(alignment: .leading, spacing: 12) {
                                HStack {
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text(pending.credentialName ?? pending.request.secretID.rawValue)
                                            .font(.headline)
                                        Text(pending.request.reason)
                                            .foregroundStyle(.secondary)
                                    }
                                    Spacer()
                                    Text(pending.request.client.rawValue.capitalized)
                                        .font(.caption.weight(.medium))
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 4)
                                        .background(.quaternary, in: Capsule())
                                }
                                LabeledContent("Destination", value: pending.request.consumerID.rawValue)
                                LabeledContent("Target", value: pending.request.targetID.rawValue)
                                HStack {
                                    Button("Deny", role: .destructive) {
                                        model.deny(pending)
                                    }
                                    if pending.credentialName == nil {
                                        Button("Add credential", systemImage: "plus") {
                                            model.presentMissingCredential(pending)
                                        }
                                    }
                                    Spacer()
                                    Button("Approve", systemImage: "checkmark.shield.fill") {
                                        Task { await model.approve(pending) }
                                    }
                                    .buttonStyle(.borderedProminent)
                                }
                                .disabled(model.processingRequestIDs.contains(pending.id))
                            }
                            .padding(16)
                            .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 14))
                        }
                    }
                }
            }
        }
        .padding(24)
    }
}

private struct StoreCredentialEntryView: View {
    private enum EntryMode: String, CaseIterable, Identifiable {
        case single = "Key or password"
        case usernamePassword = "Username and password"
        var id: Self { self }
    }

    let model: StoreBridgeModel
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var mode: EntryMode = .single
    @State private var value = ""
    @State private var username = ""
    @State private var password = ""
    @State private var allowsCompanionApproval: Bool
    @State private var isSaving = false
    @FocusState private var focused: Bool

    init(model: StoreBridgeModel) {
        self.model = model
        _allowsCompanionApproval = State(initialValue: model.companionApprovalDefault)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Add credential")
                    .font(.title2.weight(.semibold))
                Text("That’s all KeyCourier needs from you.")
                    .foregroundStyle(.secondary)
            }
            TextField("Credential name", text: $name)
                .textFieldStyle(.roundedBorder)
            Picker("Type", selection: $mode) {
                ForEach(EntryMode.allCases) { mode in Text(mode.rawValue).tag(mode) }
            }
            .pickerStyle(.segmented)

            if mode == .single {
                SecureField("Paste key or password", text: $value)
                    .textFieldStyle(.roundedBorder)
                    .focused($focused)
            } else {
                TextField("Username", text: $username)
                    .textFieldStyle(.roundedBorder)
                    .focused($focused)
                SecureField("Password", text: $password)
                    .textFieldStyle(.roundedBorder)
            }

            if model.companionConfiguration.isEnabled {
                Toggle("Allow paired iPhone approval", isOn: $allowsCompanionApproval)
                Text("The iPhone can approve this credential without showing its value.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            HStack {
                Button("Cancel") {
                    clear()
                    dismiss()
                }
                Spacer()
                Button("Save") { Task { await save() } }
                    .buttonStyle(.borderedProminent)
                    .disabled(!canSave || isSaving)
            }
        }
        .padding(24)
        .frame(width: 440)
        .onAppear {
            allowsCompanionApproval = model.companionConfiguration.isEnabled
                && model.companionApprovalDefault
            focused = true
        }
        .onChange(of: mode) {
            if mode == .single {
                username = ""
                password = ""
            } else {
                value = ""
            }
            focused = true
        }
    }

    private var canSave: Bool {
        {
            switch mode {
            case .single: !value.isEmpty
            case .usernamePassword:
                !username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !password.isEmpty
            }
        }()
    }

    private func save() async {
        isSaving = true
        let capturedName = name
        let material: CompanionCredentialMaterial
        let materialKind: SecretMaterialKind
        switch mode {
        case .single:
            material = .single(Data(value.utf8))
            materialKind = .single
        case .usernamePassword:
            material = .usernamePassword(username: username, password: Data(password.utf8))
            materialKind = .usernamePassword
        }
        clear()
        if await model.saveCredential(
            name: capturedName,
            material: material,
            materialKind: materialKind,
            allowsCompanionApproval: allowsCompanionApproval
        ) {
            dismiss()
        } else {
            isSaving = false
        }
    }

    private func clear() {
        value = ""
        username = ""
        password = ""
    }
}

private struct StoreRequestedCredentialEntryView: View {
    private enum EntryMode: String, CaseIterable, Identifiable {
        case single = "Key or password"
        case usernamePassword = "Username and password"
        var id: Self { self }
    }

    private enum Field: Hashable {
        case value
        case username
        case password
    }

    let model: StoreBridgeModel
    let request: StorePendingRequest
    @Environment(\.dismiss) private var dismiss
    @State private var name: String
    @State private var mode: EntryMode = .single
    @State private var value = ""
    @State private var username = ""
    @State private var password = ""
    @State private var allowsCompanionApproval: Bool
    @State private var isSaving = false
    @FocusState private var focused: Field?

    init(model: StoreBridgeModel, request: StorePendingRequest) {
        self.model = model
        self.request = request
        _name = State(initialValue: request.suggestedCredentialName)
        _allowsCompanionApproval = State(initialValue: model.companionApprovalDefault)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Add credential")
                    .font(.title2.weight(.semibold))
                Text("KeyCourier needs this credential for " + request.request.client.rawValue.capitalized + ".")
                    .foregroundStyle(.secondary)
            }

            TextField("Credential name", text: $name)
                .textFieldStyle(.roundedBorder)
            Picker("Type", selection: $mode) {
                ForEach(EntryMode.allCases) { mode in
                    Text(mode.rawValue).tag(mode)
                }
            }
            .pickerStyle(.segmented)

            if mode == .single {
                SecureField("Paste key or password", text: $value)
                    .textFieldStyle(.roundedBorder)
                    .focused($focused, equals: .value)
            } else {
                TextField("Username", text: $username)
                    .textFieldStyle(.roundedBorder)
                    .focused($focused, equals: .username)
                SecureField("Password", text: $password)
                    .textFieldStyle(.roundedBorder)
                    .focused($focused, equals: .password)
            }

            if model.companionConfiguration.isEnabled {
                Toggle("Allow paired iPhone approval", isOn: $allowsCompanionApproval)
            }

            HStack {
                Button("Cancel") {
                    clear()
                    model.dismissMissingCredentialRequest()
                    dismiss()
                }
                Spacer()
                Button("Save") { Task { await save() } }
                    .buttonStyle(.borderedProminent)
                    .disabled(!canSave || isSaving)
            }
        }
        .padding(24)
        .frame(width: 440)
        .onAppear {
            allowsCompanionApproval = model.companionConfiguration.isEnabled
                && model.companionApprovalDefault
            focused = .value
        }
        .onChange(of: mode) {
            if mode == .single {
                username = ""
                password = ""
                focused = .value
            } else {
                value = ""
                focused = .username
            }
        }
    }

    private var canSave: Bool {
        switch mode {
        case .single:
            return !value.isEmpty
        case .usernamePassword:
            return !username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                && !password.isEmpty
        }
    }

    private func save() async {
        isSaving = true
        let capturedName = name
        let material: CompanionCredentialMaterial
        let materialKind: SecretMaterialKind
        switch mode {
        case .single:
            material = .single(Data(value.utf8))
            materialKind = .single
        case .usernamePassword:
            material = .usernamePassword(username: username, password: Data(password.utf8))
            materialKind = .usernamePassword
        }
        clear()
        if await model.saveRequestedCredential(
            name: capturedName,
            pending: request,
            material: material,
            materialKind: materialKind,
            allowsCompanionApproval: allowsCompanionApproval
        ) {
            dismiss()
        } else {
            isSaving = false
        }
    }

    private func clear() {
        name = ""
        value = ""
        username = ""
        password = ""
        focused = nil
    }
}

private enum StoreCredentialReplacementMode: String, CaseIterable, Identifiable {
    case single = "Key or password"
    case usernamePassword = "Username and password"

    var id: Self { self }
}

private struct StoreCredentialReplacementView: View {
    let model: StoreBridgeModel
    let credential: SecretMetadata
    @Environment(\.dismiss) private var dismiss
    @State private var mode: StoreCredentialReplacementMode
    @State private var value = ""
    @State private var username = ""
    @State private var password = ""
    @State private var allowsCompanionApproval: Bool
    @State private var isSaving = false
    @State private var submissionError: String?
    @FocusState private var focused: Field?

    private enum Field: Hashable {
        case value
        case username
        case password
    }

    init(model: StoreBridgeModel, credential: SecretMetadata) {
        self.model = model
        self.credential = credential
        _mode = State(
            initialValue: credential.materialKind == .usernamePassword
                ? .usernamePassword
                : .single
        )
        _allowsCompanionApproval = State(initialValue: credential.allowsCompanionApproval)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Replace credential")
                    .font(.title2.weight(.semibold))
                Text(credential.displayName)
                    .foregroundStyle(.secondary)
            }

            Picker("Format", selection: $mode) {
                ForEach(StoreCredentialReplacementMode.allCases) { mode in
                    Text(mode.rawValue).tag(mode)
                }
            }
            .pickerStyle(.segmented)

            if mode == .single {
                SecureField("Paste replacement key or password", text: $value)
                    .textFieldStyle(.roundedBorder)
                    .focused($focused, equals: .value)
            } else {
                TextField("Username", text: $username)
                    .textFieldStyle(.roundedBorder)
                    .focused($focused, equals: .username)
                SecureField("Password", text: $password)
                    .textFieldStyle(.roundedBorder)
                    .focused($focused, equals: .password)
            }

            if model.companionConfiguration.isEnabled || credential.allowsCompanionApproval {
                Toggle("Allow paired iPhone approval", isOn: $allowsCompanionApproval)
                    .disabled(!model.companionConfiguration.isEnabled && !credential.allowsCompanionApproval)
                Text("Changing this access always requires a fresh value and rewrites the protected Keychain item.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            HStack {
                Button("Cancel") {
                    clear()
                    dismiss()
                }
                Spacer()
                Button("Save") { Task { await save() } }
                    .buttonStyle(.borderedProminent)
                    .disabled(!canSave || isSaving)
            }
        }
        .padding(24)
        .frame(width: 440)
        .onAppear { focused = mode == .single ? .value : .username }
        .onChange(of: mode) {
            if mode == .single {
                username = ""
                password = ""
                focused = .value
            } else {
                value = ""
                focused = .username
            }
        }
        .alert("Credential was not replaced", isPresented: submissionErrorBinding) {
            Button("OK", role: .cancel) { submissionError = nil }
        } message: {
            Text(submissionError ?? "Unknown error")
        }
    }

    private var canSave: Bool {
        switch mode {
        case .single:
            !value.isEmpty
        case .usernamePassword:
            !username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !password.isEmpty
        }
    }

    private var submissionErrorBinding: Binding<Bool> {
        Binding(get: { submissionError != nil }, set: { if !$0 { submissionError = nil } })
    }

    private func save() async {
        isSaving = true
        let material: CompanionCredentialMaterial
        let materialKind: SecretMaterialKind
        switch mode {
        case .single:
            material = .single(Data(value.utf8))
            materialKind = .single
        case .usernamePassword:
            material = .usernamePassword(username: username, password: Data(password.utf8))
            materialKind = .usernamePassword
        }
        clear()
        if await model.replaceCredential(
            credential,
            material: material,
            materialKind: materialKind,
            allowsCompanionApproval: allowsCompanionApproval
        ) {
            dismiss()
        } else {
            submissionError = model.errorMessage ?? "The credential could not be replaced."
            isSaving = false
        }
    }

    private func clear() {
        value = ""
        username = ""
        password = ""
        focused = nil
    }
}

private struct StoreCompanionView: View {
    let model: StoreBridgeModel
    @State private var showingTurnOffConfirmation = false

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                Text("iPhone companion")
                    .font(.title2.weight(.semibold))
                Text("Pair one iPhone to receive approval notifications and add credentials securely.")
                    .foregroundStyle(.secondary)
            }

            if !model.companionConfiguration.isEnabled {
                ContentUnavailableView(
                    "iPhone companion is off",
                    systemImage: "iphone.slash",
                    description: Text("Turn it on to pair an iPhone through your private iCloud account.")
                )
                Button("Enable iPhone companion", systemImage: "iphone.gen3") {
                    Task { await model.setCompanionEnabled(true) }
                }
                .buttonStyle(.borderedProminent)
            } else {
                Toggle(
                    "Allow iPhone approval for new credentials",
                    isOn: Binding(
                        get: { model.companionApprovalDefault },
                        set: { model.setCompanionApprovalDefault($0) }
                    )
                )
                Text("This applies to credentials you add from this Mac. Credential values stay in the protected Keychain and are never sent to the iPhone.")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                if let trusted = model.companionConfiguration.trustedDevice {
                    VStack(alignment: .leading, spacing: 10) {
                        Label("Paired with " + trusted.registration.deviceName, systemImage: "checkmark.seal.fill")
                            .font(.headline)
                            .foregroundStyle(.green)
                        if let pairingCode = model.companionPairingCode {
                            Text("Confirm this code on the iPhone")
                                .foregroundStyle(.secondary)
                            Text(pairingCode)
                                .font(.system(.title3, design: .monospaced).weight(.semibold))
                                .textSelection(.enabled)
                        }
                        Button("Remove paired iPhone", role: .destructive) {
                            Task { await model.removeTrustedCompanion() }
                        }
                    }
                    .padding(16)
                    .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 12))
                } else if model.companionRegistrations.isEmpty {
                    ContentUnavailableView(
                        "Waiting for an iPhone",
                        systemImage: "iphone",
                        description: Text("Open KeyCourier on the iPhone and choose Pair this iPhone.")
                    )
                } else {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("iPhone registrations")
                            .font(.headline)
                        ForEach(model.companionRegistrations) { registration in
                            HStack {
                                Label(registration.deviceName, systemImage: "iphone")
                                Spacer()
                                Button("Decline", role: .destructive) {
                                    Task { await model.declineCompanionRegistration(registration) }
                                }
                                Button("Pair") {
                                    Task { await model.approveCompanionRegistration(registration) }
                                }
                                .buttonStyle(.borderedProminent)
                            }
                            .padding(10)
                            .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 10))
                        }
                    }
                }

                if let status = model.companionStatusMessage {
                    Text(status).foregroundStyle(.secondary)
                }
                Button("Turn off iPhone companion", role: .destructive) {
                    showingTurnOffConfirmation = true
                }
            }

            if let error = model.errorMessage {
                Text(error).foregroundStyle(.red)
            }
            Spacer(minLength: 0)
        }
        .padding(24)
        .frame(minWidth: 500, minHeight: 360)
        .confirmationDialog(
            "Turn off iPhone companion?",
            isPresented: $showingTurnOffConfirmation,
            titleVisibility: .visible
        ) {
            Button("Turn Off", role: .destructive) {
                Task { await model.setCompanionEnabled(false) }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This permanently removes pending approvals and encrypted credential additions waiting in iCloud.")
        }
    }
}

private struct StoreStatusView: View {
    let model: StoreBridgeModel
    @State private var confirmedPairingCodes: Set<String> = []

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(spacing: 10) {
                Label("KeyCourier for Mac", systemImage: "key.viewfinder")
                    .font(.title2.weight(.semibold))
                Spacer()
                Button("Refresh", systemImage: "arrow.clockwise") {
                    model.refresh()
                }
                .labelStyle(.iconOnly)
                .help("Refresh bridge pairing")
            }

            Divider()

            VStack(alignment: .leading, spacing: 6) {
                Text("Bridge setup")
                    .font(.headline)
                Text(model.statusMessage)
                    .foregroundStyle(.secondary)
                if model.pendingRequestCount > 0 {
                    Label(
                        "\(model.pendingRequestCount) authenticated request\(model.pendingRequestCount == 1 ? "" : "s") waiting in the Requests tab",
                        systemImage: "bell.badge"
                    )
                    .foregroundStyle(.secondary)
                }
                if let errorMessage = model.errorMessage {
                    Text(errorMessage)
                        .foregroundStyle(.red)
                }
            }

            if model.pairings.isEmpty, let trustedBridgeID = model.trustedBridgeID {
                VStack(alignment: .leading, spacing: 10) {
                    Label("Bridge trusted", systemImage: "checkmark.seal.fill")
                        .font(.headline)
                        .foregroundStyle(.green)
                    Text("Bridge \(trustedBridgeID.uuidString.lowercased())")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text("Authenticated requests are reviewed in the Requests tab.")
                        .foregroundStyle(.secondary)
                    Button("Unpair bridge", role: .destructive) {
                        Task { await model.unpairBridge() }
                    }
                }
                .padding(16)
                .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 12))
            } else if model.pairings.isEmpty {
                ContentUnavailableView(
                    "No bridge found",
                    systemImage: "link.badge.plus",
                    description: Text("Run keycourier-bridge pair, then return here.")
                )
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 12) {
                        ForEach(model.pairings) { pairing in
                            pairingRow(pairing)
                        }
                    }
                }
            }

            Spacer(minLength: 0)
        }
        .padding(24)
        .frame(minWidth: 500, minHeight: 360)
    }

    @ViewBuilder
    private func pairingRow(_ pairing: StoreBridgePairing) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text(pairing.registration.displayName)
                        .font(.headline)
                    Text("Bridge \(pairing.registration.bridgeID.uuidString.lowercased())")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if pairing.isTrusted {
                    VStack(alignment: .trailing, spacing: 6) {
                        Label("Trusted", systemImage: "checkmark.seal.fill")
                            .foregroundStyle(.green)
                        Button("Unpair", role: .destructive) {
                            Task { await model.unpairBridge() }
                        }
                    }
                } else {
                    Button("Trust this bridge") {
                        Task {
                            await model.trust(
                                pairing,
                                confirmedPairingCode: confirmedPairingCodes.contains(pairing.pairingCode)
                                    ? pairing.pairingCode
                                    : nil
                            )
                            confirmedPairingCodes.remove(pairing.pairingCode)
                        }
                    }
                    .disabled(
                        model.isTrustingBridge ||
                        !confirmedPairingCodes.contains(pairing.pairingCode)
                    )
                }
            }

            VStack(alignment: .leading, spacing: 4) {
                Text("Compare this code with the bridge terminal")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Text(pairing.pairingCode)
                    .font(.system(.title3, design: .monospaced).weight(.semibold))
                    .textSelection(.enabled)
                    .accessibilityLabel("Pairing code \(pairing.pairingCode)")
                if !pairing.isTrusted {
                    Toggle(
                        "I confirmed the codes match",
                        isOn: Binding(
                            get: { confirmedPairingCodes.contains(pairing.pairingCode) },
                            set: { confirmed in
                                if confirmed {
                                    confirmedPairingCodes.insert(pairing.pairingCode)
                                } else {
                                    confirmedPairingCodes.remove(pairing.pairingCode)
                                }
                            }
                        )
                    )
                    .toggleStyle(.checkbox)
                }
            }
        }
        .padding(14)
        .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 12))
    }
}

import CryptoKit
import Foundation

public struct BridgeApprovalDispatcher: Sendable {
    private let secretStore: any SecretStore
    private let ownerAuthorizer: any OwnerPresenceAuthorizing

    public init(
        secretStore: any SecretStore,
        ownerAuthorizer: any OwnerPresenceAuthorizing
    ) {
        self.secretStore = secretStore
        self.ownerAuthorizer = ownerAuthorizer
    }

    public func approve(
        _ signedRequest: SignedBridgeRequest,
        pinnedBridge: BridgePinnedPeer,
        storeIdentity: BridgeIdentity,
        secrets: [SecretMetadata],
        queue: BridgeQueue,
        at date: Date = Date()
    ) async throws -> BridgeDeliveryCommand {
        try await approve(
            signedRequest,
            pinnedBridge: pinnedBridge,
            storeIdentity: storeIdentity,
            secrets: secrets,
            queue: queue,
            at: date,
            requiresOwnerPresence: true
        )
    }

    /// Approve a bridge request after an already-authenticated companion has
    /// made the decision. The caller must verify the companion decision and
    /// its request digest before calling this method. The credential also
    /// must be explicitly marked as companion-eligible.
    public func approveFromCompanion(
        _ signedRequest: SignedBridgeRequest,
        pinnedBridge: BridgePinnedPeer,
        storeIdentity: BridgeIdentity,
        secrets: [SecretMetadata],
        queue: BridgeQueue,
        at date: Date = Date()
    ) async throws -> BridgeDeliveryCommand {
        try await approve(
            signedRequest,
            pinnedBridge: pinnedBridge,
            storeIdentity: storeIdentity,
            secrets: secrets,
            queue: queue,
            at: date,
            requiresOwnerPresence: false
        )
    }

    private func approve(
        _ signedRequest: SignedBridgeRequest,
        pinnedBridge: BridgePinnedPeer,
        storeIdentity: BridgeIdentity,
        secrets: [SecretMetadata],
        queue: BridgeQueue,
        at date: Date,
        requiresOwnerPresence: Bool
    ) async throws -> BridgeDeliveryCommand {
        let request = signedRequest.request
        try validate(
            signedRequest,
            pinnedBridge: pinnedBridge,
            secrets: secrets,
            requiresCompanionApproval: !requiresOwnerPresence,
            at: date
        )
        let storeSigningPublicKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: storeIdentity.keys.signingPrivateKey
        ).publicKey.rawRepresentation

        if let existing = try queue.command(forRequestID: request.id, at: date) {
            try validate(
                existing,
                for: signedRequest,
                pinnedBridge: pinnedBridge,
                storeSigningPublicKey: storeSigningPublicKey,
                at: date
            )
            guard existing.action == .deliver else {
                throw BridgeProtocolError.conflictingRecord
            }
            _ = try queue.claimRequest(signedRequest, at: date)
            return existing
        }

        if requiresOwnerPresence {
            try await ownerAuthorizer.authorize(reason: "Approve KeyCourier credential delivery")
        }
        guard let secret = try await secretStore.read(
            id: request.secretID,
            reason: "Approve KeyCourier credential delivery"
        ), let agreementKey = pinnedBridge.keyAgreementPublicKey else {
            throw BridgeProtocolError.invalidRecord
        }
        let command = try BridgeCrypto.makeDeliveryCommand(
            request: request,
            bridgeID: pinnedBridge.bridgeID,
            recipientPublicKey: agreementKey,
            secret: secret,
            appSigningPrivateKey: storeIdentity.keys.signingPrivateKey,
            commandID: request.id,
            createdAt: date,
            expiresAt: request.expiresAt
        )
        _ = try queue.enqueue(command)
        _ = try queue.claimRequest(signedRequest, at: date)
        return command
    }

    public func deny(
        _ signedRequest: SignedBridgeRequest,
        pinnedBridge: BridgePinnedPeer,
        storeIdentity: BridgeIdentity,
        queue: BridgeQueue,
        at date: Date = Date()
    ) throws -> BridgeDeliveryCommand {
        try BridgeCrypto.verify(
            signedRequest,
            signingPublicKey: pinnedBridge.signingPublicKey,
            expectedBridgeID: pinnedBridge.bridgeID,
            at: date
        )
        if let existing = try queue.command(forRequestID: signedRequest.id, at: date) {
            let storeSigningPublicKey = try Curve25519.Signing.PrivateKey(
                rawRepresentation: storeIdentity.keys.signingPrivateKey
            ).publicKey.rawRepresentation
            try validate(
                existing,
                for: signedRequest,
                pinnedBridge: pinnedBridge,
                storeSigningPublicKey: storeSigningPublicKey,
                at: date
            )
            guard existing.action == .deny else {
                throw BridgeProtocolError.conflictingRecord
            }
            _ = try queue.claimRequest(signedRequest, at: date)
            return existing
        }
        let command = try BridgeCrypto.makeDenyCommand(
            request: signedRequest.request,
            bridgeID: pinnedBridge.bridgeID,
            appSigningPrivateKey: storeIdentity.keys.signingPrivateKey,
            commandID: signedRequest.id,
            createdAt: date,
            expiresAt: signedRequest.request.expiresAt
        )
        _ = try queue.enqueue(command)
        _ = try queue.claimRequest(signedRequest, at: date)
        return command
    }

    private func validate(
        _ signedRequest: SignedBridgeRequest,
        pinnedBridge: BridgePinnedPeer,
        secrets: [SecretMetadata],
        requiresCompanionApproval: Bool = false,
        at date: Date
    ) throws {
        guard pinnedBridge.keyAgreementPublicKey != nil else {
            throw BridgeStorageError.invalidIdentity
        }
        try BridgeCrypto.verify(
            signedRequest,
            signingPublicKey: pinnedBridge.signingPublicKey,
            expectedBridgeID: pinnedBridge.bridgeID,
            at: date
        )
        guard let metadata = secrets.first(where: { $0.secretID == signedRequest.request.secretID }),
              metadata.expiresAt.map({ $0 > date }) ?? true else {
            throw BridgeProtocolError.invalidRecord
        }
        if requiresCompanionApproval {
            guard metadata.allowsCompanionApproval else {
                throw BridgeProtocolError.invalidRecord
            }
        }
    }

    private func validate(
        _ command: BridgeDeliveryCommand,
        for signedRequest: SignedBridgeRequest,
        pinnedBridge: BridgePinnedPeer,
        storeSigningPublicKey: Data,
        at date: Date
    ) throws {
        let request = signedRequest.request
        try BridgeCrypto.verify(
            command,
            appSigningPublicKey: storeSigningPublicKey,
            expectedBridgeID: pinnedBridge.bridgeID,
            expectedRequestDigest: try BridgeCrypto.requestDigest(for: request),
            at: date
        )
        guard command.requestID == request.id,
              command.targetID == request.targetID,
              command.consumerID == request.consumerID else {
            throw BridgeProtocolError.invalidRecord
        }
    }
}

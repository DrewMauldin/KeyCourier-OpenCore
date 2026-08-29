import CryptoKit
import Foundation

public struct BridgeCommandProcessor: Sendable {
    public typealias ProfileResolver = @Sendable (ConsumerID) throws -> ConsumerProfile?
    public typealias Installer = @Sendable (Data, ConsumerProfile) async throws -> Void

    private let queue: BridgeQueue
    private let identity: BridgeIdentity
    private let pinnedStore: BridgePinnedPeer
    private let profile: ProfileResolver
    private let install: Installer

    public init(
        queue: BridgeQueue,
        identity: BridgeIdentity,
        pinnedStore: BridgePinnedPeer,
        profile: @escaping ProfileResolver,
        install: @escaping Installer
    ) {
        self.queue = queue
        self.identity = identity
        self.pinnedStore = pinnedStore
        self.profile = profile
        self.install = install
    }

    public func process(
        _ command: BridgeDeliveryCommand,
        at date: Date = Date()
    ) async throws -> SignedBridgeReceipt {
        guard pinnedStore.bridgeID == identity.id,
              pinnedStore.keyAgreementPublicKey == nil else {
            throw BridgeStorageError.invalidIdentity
        }
        try BridgeCrypto.verify(
            command,
            appSigningPublicKey: pinnedStore.signingPublicKey,
            expectedBridgeID: identity.id,
            at: date
        )

        if let existing = try queue.receipt(for: command.commandID) {
            try verify(existing, for: command)
            return existing
        }

        let destination: ConsumerProfile?
        let destinationFailureCode: ReceiptCode?
        switch command.action {
        case .deny:
            destination = nil
            destinationFailureCode = nil
        case .deliver:
            if let resolved = try profile(command.consumerID) {
                guard resolved.id == command.consumerID else {
                    throw BridgeProtocolError.invalidRecord
                }
                if resolved.targetID == command.targetID {
                    destination = resolved
                    destinationFailureCode = nil
                } else {
                    destination = nil
                    destinationFailureCode = .validationFailed
                }
            } else {
                destination = nil
                destinationFailureCode = .consumerMissing
            }
        }

        guard try queue.claimCommand(command, at: date) == .claimed else {
            throw BridgeProtocolError.claimExists
        }

        let outcome: RequestReceipt
        switch command.action {
        case .deny:
            outcome = receipt(for: command, status: .denied, code: .ownerDenied, at: date)
        case .deliver:
            if let destinationFailureCode {
                outcome = receipt(
                    for: command,
                    status: .notConfigured,
                    code: destinationFailureCode,
                    at: date
                )
                break
            }
            do {
                guard let destination else { throw BridgeProtocolError.invalidRecord }
                let secret = try BridgeCrypto.openDeliveryCommand(
                    command,
                    recipientPrivateKey: identity.keys.keyAgreementPrivateKey,
                    appSigningPublicKey: pinnedStore.signingPublicKey,
                    expectedBridgeID: identity.id,
                    expectedRequestDigest: command.requestDigest,
                    at: date
                )
                try await install(secret, destination)
                outcome = receipt(
                    for: command,
                    status: .verified,
                    code: .consumerVerified,
                    at: date
                )
            } catch {
                outcome = receipt(
                    for: command,
                    status: .failed,
                    code: .deliveryFailed,
                    at: date
                )
            }
        }

        let signed = try BridgeCrypto.sign(
            SignedBridgeReceipt(
                bridgeID: identity.id,
                commandID: command.commandID,
                requestDigest: command.requestDigest,
                receipt: outcome
            ),
            privateKey: identity.keys.signingPrivateKey
        )
        _ = try queue.record(signed)
        guard let persisted = try queue.receipt(for: command.commandID) else {
            throw BridgeProtocolError.invalidRecord
        }
        try verify(persisted, for: command)
        return persisted
    }

    private func verify(
        _ receipt: SignedBridgeReceipt,
        for command: BridgeDeliveryCommand
    ) throws {
        try BridgeCrypto.verify(
            receipt,
            signingPublicKey: signingPublicKey,
            expectedBridgeID: identity.id,
            expectedCommandID: command.commandID,
            expectedRequestID: command.requestID,
            expectedRequestDigest: command.requestDigest
        )
        guard receipt.receipt.targetID == command.targetID,
              receipt.receipt.consumerID == command.consumerID else {
            throw BridgeProtocolError.invalidRecord
        }
    }

    private var signingPublicKey: Data {
        get throws {
            try Curve25519.Signing.PrivateKey(
                rawRepresentation: identity.keys.signingPrivateKey
            ).publicKey.rawRepresentation
        }
    }

    private func receipt(
        for command: BridgeDeliveryCommand,
        status: ReceiptStatus,
        code: ReceiptCode,
        at date: Date
    ) -> RequestReceipt {
        RequestReceipt(
            requestID: command.requestID,
            status: status,
            targetID: command.targetID,
            consumerID: command.consumerID,
            code: code,
            recordedAt: date
        )
    }
}

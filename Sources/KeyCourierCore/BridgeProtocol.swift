import CryptoKit
import Foundation

public enum BridgeProtocolError: Error, Equatable, LocalizedError, Sendable {
    case invalidRecord
    case invalidSignature
    case expired
    case invalidKey
    case decryptionFailed
    case replayedRecord
    case conflictingRecord
    case queueLimitExceeded
    case claimExists
    case unknownDeliveryState

    public var errorDescription: String? {
        switch self {
        case .invalidRecord: "The bridge record is invalid."
        case .invalidSignature: "The bridge record signature is invalid."
        case .expired: "The bridge record has expired."
        case .invalidKey: "The bridge key material is invalid."
        case .decryptionFailed: "The bridge command could not be opened."
        case .replayedRecord: "The bridge record has already been consumed."
        case .conflictingRecord: "A bridge record with this identifier has different content."
        case .queueLimitExceeded: "The bridge queue is full."
        case .claimExists: "The bridge capability has already been claimed."
        case .unknownDeliveryState: "The bridge delivery outcome is unknown."
        }
    }
}

private enum BridgeProtocolLimits {
    static let schemaVersion = 1
    static let keyBytes = 32
    static let signatureBytes = 64
    static let nonceBytes = 32
    static let maximumDisplayName = 80
    static let maximumCiphertextBytes = 128 * 1024
    static let maximumSecretBytes = 64 * 1024
    static let pairingLifetime: TimeInterval = 5 * 60
    static let maximumLifetime: TimeInterval = 24 * 60 * 60
    static let futureSkew: TimeInterval = 5 * 60
    static let zeroUUID = UUID(uuidString: "00000000-0000-0000-0000-000000000000")!
}

public struct BridgePrivateKeys: Equatable, Sendable {
    public let signingPrivateKey: Data
    public let keyAgreementPrivateKey: Data

    public init(signingPrivateKey: Data, keyAgreementPrivateKey: Data) throws {
        do {
            _ = try Curve25519.Signing.PrivateKey(rawRepresentation: signingPrivateKey)
            _ = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: keyAgreementPrivateKey)
        } catch {
            throw BridgeProtocolError.invalidKey
        }
        self.signingPrivateKey = signingPrivateKey
        self.keyAgreementPrivateKey = keyAgreementPrivateKey
    }
}

public struct BridgeRegistration: Codable, Sendable, Equatable {
    public static let currentSchemaVersion = BridgeProtocolLimits.schemaVersion

    public let schemaVersion: Int
    public let bridgeID: UUID
    public let displayName: String
    public let signingPublicKey: Data
    public let keyAgreementPublicKey: Data
    public let bridgeNonce: Data
    public let createdAt: Date
    public let expiresAt: Date
    public var signature: Data

    public init(
        schemaVersion: Int = Self.currentSchemaVersion,
        bridgeID: UUID,
        displayName: String,
        signingPublicKey: Data,
        keyAgreementPublicKey: Data,
        bridgeNonce: Data,
        createdAt: Date = Date(),
        expiresAt: Date? = nil,
        signature: Data = Data()
    ) throws {
        self.schemaVersion = schemaVersion
        self.bridgeID = bridgeID
        self.displayName = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        self.signingPublicKey = signingPublicKey
        self.keyAgreementPublicKey = keyAgreementPublicKey
        self.bridgeNonce = bridgeNonce
        self.createdAt = createdAt
        self.expiresAt = expiresAt ?? createdAt.addingTimeInterval(BridgeProtocolLimits.pairingLifetime)
        self.signature = signature
        try validateUnsigned(at: createdAt)
    }

    public func validate(at date: Date = Date()) throws {
        try validateUnsigned(at: date)
        guard signature.count == BridgeProtocolLimits.signatureBytes else {
            throw BridgeProtocolError.invalidSignature
        }
        guard date <= expiresAt else { throw BridgeProtocolError.expired }
    }

    public func signingPayload() throws -> Data {
        try validateUnsigned(at: createdAt)
        var data = Data()
        data.bridgeAppendField("KeyCourier.Bridge.Registration.v1")
        data.bridgeAppendField(bridgeID)
        data.bridgeAppendField(displayName)
        data.bridgeAppendField(signingPublicKey)
        data.bridgeAppendField(keyAgreementPublicKey)
        data.bridgeAppendField(bridgeNonce)
        data.bridgeAppendInteger(try BridgeDate.milliseconds(createdAt))
        data.bridgeAppendInteger(try BridgeDate.milliseconds(expiresAt))
        return data
    }

    public func digest() throws -> Data {
        Data(SHA256.hash(data: try signingPayload()))
    }

    private func validateUnsigned(at date: Date) throws {
        guard schemaVersion == Self.currentSchemaVersion,
              !displayName.isEmpty,
              displayName.count <= BridgeProtocolLimits.maximumDisplayName,
              displayName.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }),
              signingPublicKey.count == BridgeProtocolLimits.keyBytes,
              keyAgreementPublicKey.count == BridgeProtocolLimits.keyBytes,
              bridgeNonce.count == BridgeProtocolLimits.nonceBytes,
              (try? BridgeDate.milliseconds(createdAt)) != nil,
              (try? BridgeDate.milliseconds(expiresAt)) != nil else {
            throw BridgeProtocolError.invalidRecord
        }
        guard let _ = try? Curve25519.Signing.PublicKey(rawRepresentation: signingPublicKey),
              let _ = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: keyAgreementPublicKey) else {
            throw BridgeProtocolError.invalidKey
        }
        let duration = expiresAt.timeIntervalSince(createdAt)
        guard duration > 0, duration <= BridgeProtocolLimits.pairingLifetime else {
            throw BridgeProtocolError.invalidRecord
        }
        guard createdAt <= date.addingTimeInterval(BridgeProtocolLimits.futureSkew) else {
            throw BridgeProtocolError.invalidRecord
        }
    }
}

public struct BridgePairingProposal: Codable, Sendable, Equatable {
    public static let currentSchemaVersion = BridgeProtocolLimits.schemaVersion

    public let schemaVersion: Int
    public let bridgeID: UUID
    public let registrationDigest: Data
    public let appSigningPublicKey: Data
    public let appNonce: Data
    public let createdAt: Date
    public let expiresAt: Date
    public var signature: Data

    public init(
        schemaVersion: Int = Self.currentSchemaVersion,
        bridgeID: UUID,
        registrationDigest: Data,
        appSigningPublicKey: Data,
        appNonce: Data,
        createdAt: Date = Date(),
        expiresAt: Date? = nil,
        signature: Data = Data()
    ) throws {
        self.schemaVersion = schemaVersion
        self.bridgeID = bridgeID
        self.registrationDigest = registrationDigest
        self.appSigningPublicKey = appSigningPublicKey
        self.appNonce = appNonce
        self.createdAt = createdAt
        self.expiresAt = expiresAt ?? createdAt.addingTimeInterval(BridgeProtocolLimits.pairingLifetime)
        self.signature = signature
        try validateUnsigned(at: createdAt)
    }

    public func validate(at date: Date = Date()) throws {
        try validateUnsigned(at: date)
        guard signature.count == BridgeProtocolLimits.signatureBytes else {
            throw BridgeProtocolError.invalidSignature
        }
        guard date <= expiresAt else { throw BridgeProtocolError.expired }
    }

    public func signingPayload() throws -> Data {
        try validateUnsigned(at: createdAt)
        var data = Data()
        data.bridgeAppendField("KeyCourier.Bridge.PairingProposal.v1")
        data.bridgeAppendField(bridgeID)
        data.bridgeAppendField(registrationDigest)
        data.bridgeAppendField(appSigningPublicKey)
        data.bridgeAppendField(appNonce)
        data.bridgeAppendInteger(try BridgeDate.milliseconds(createdAt))
        data.bridgeAppendInteger(try BridgeDate.milliseconds(expiresAt))
        return data
    }

    public func digest() throws -> Data {
        Data(SHA256.hash(data: try signingPayload()))
    }

    private func validateUnsigned(at date: Date) throws {
        guard schemaVersion == Self.currentSchemaVersion,
              registrationDigest.count == SHA256.byteCount,
              appSigningPublicKey.count == BridgeProtocolLimits.keyBytes,
              appNonce.count == BridgeProtocolLimits.nonceBytes,
              (try? BridgeDate.milliseconds(createdAt)) != nil,
              (try? BridgeDate.milliseconds(expiresAt)) != nil else {
            throw BridgeProtocolError.invalidRecord
        }
        guard (try? Curve25519.Signing.PublicKey(rawRepresentation: appSigningPublicKey)) != nil else {
            throw BridgeProtocolError.invalidKey
        }
        let duration = expiresAt.timeIntervalSince(createdAt)
        guard duration > 0, duration <= BridgeProtocolLimits.pairingLifetime else {
            throw BridgeProtocolError.invalidRecord
        }
        guard createdAt <= date.addingTimeInterval(BridgeProtocolLimits.futureSkew) else {
            throw BridgeProtocolError.invalidRecord
        }
    }
}

public struct BridgeTrustGrant: Codable, Sendable, Equatable {
    public static let currentSchemaVersion = BridgeProtocolLimits.schemaVersion

    public let schemaVersion: Int
    public let bridgeID: UUID
    public let registrationDigest: Data
    public let proposalDigest: Data
    public let grantedAt: Date
    public var signature: Data

    public init(
        schemaVersion: Int = Self.currentSchemaVersion,
        bridgeID: UUID,
        registrationDigest: Data,
        proposalDigest: Data,
        grantedAt: Date = Date(),
        signature: Data = Data()
    ) throws {
        self.schemaVersion = schemaVersion
        self.bridgeID = bridgeID
        self.registrationDigest = registrationDigest
        self.proposalDigest = proposalDigest
        self.grantedAt = grantedAt
        self.signature = signature
        try validateUnsigned(at: grantedAt)
    }

    public func validate(at date: Date = Date()) throws {
        try validateUnsigned(at: date)
        guard signature.count == BridgeProtocolLimits.signatureBytes else {
            throw BridgeProtocolError.invalidSignature
        }
    }

    public func signingPayload() throws -> Data {
        try validateUnsigned(at: grantedAt)
        var data = Data()
        data.bridgeAppendField("KeyCourier.Bridge.TrustGrant.v1")
        data.bridgeAppendField(bridgeID)
        data.bridgeAppendField(registrationDigest)
        data.bridgeAppendField(proposalDigest)
        data.bridgeAppendInteger(try BridgeDate.milliseconds(grantedAt))
        return data
    }

    public func digest() throws -> Data {
        Data(SHA256.hash(data: try signingPayload()))
    }

    private func validateUnsigned(at date: Date) throws {
        guard schemaVersion == Self.currentSchemaVersion,
              registrationDigest.count == SHA256.byteCount,
              proposalDigest.count == SHA256.byteCount,
              (try? BridgeDate.milliseconds(grantedAt)) != nil,
              grantedAt <= date.addingTimeInterval(BridgeProtocolLimits.futureSkew) else {
            throw BridgeProtocolError.invalidRecord
        }
    }
}

public struct BridgeTrustRevocation: Codable, Sendable, Equatable, Identifiable {
    public static let currentSchemaVersion = BridgeProtocolLimits.schemaVersion

    public let schemaVersion: Int
    public let bridgeID: UUID
    public let registrationDigest: Data
    public let revokedAt: Date
    public var signature: Data

    public var id: UUID { bridgeID }

    public init(
        schemaVersion: Int = Self.currentSchemaVersion,
        bridgeID: UUID,
        registrationDigest: Data,
        revokedAt: Date = Date(),
        signature: Data = Data()
    ) throws {
        self.schemaVersion = schemaVersion
        self.bridgeID = bridgeID
        self.registrationDigest = registrationDigest
        self.revokedAt = revokedAt
        self.signature = signature
        try validateUnsigned(at: revokedAt)
    }

    public func validate(at date: Date = Date()) throws {
        try validateUnsigned(at: date)
        guard signature.count == BridgeProtocolLimits.signatureBytes else {
            throw BridgeProtocolError.invalidSignature
        }
    }

    public func signingPayload() throws -> Data {
        try validateUnsigned(at: revokedAt)
        var data = Data()
        data.bridgeAppendField("KeyCourier.Bridge.TrustRevocation.v1")
        data.bridgeAppendField(bridgeID)
        data.bridgeAppendField(registrationDigest)
        data.bridgeAppendInteger(try BridgeDate.milliseconds(revokedAt))
        return data
    }

    public func digest() throws -> Data {
        Data(SHA256.hash(data: try signingPayload()))
    }

    private func validateUnsigned(at date: Date) throws {
        guard schemaVersion == Self.currentSchemaVersion,
              bridgeID != BridgeProtocolLimits.zeroUUID,
              registrationDigest.count == SHA256.byteCount,
              (try? BridgeDate.milliseconds(revokedAt)) != nil,
              revokedAt <= date.addingTimeInterval(BridgeProtocolLimits.futureSkew) else {
            throw BridgeProtocolError.invalidRecord
        }
    }
}

public struct SignedBridgeRequest: Codable, Sendable, Equatable, Identifiable {
    public static let currentSchemaVersion = BridgeProtocolLimits.schemaVersion

    public var id: UUID { request.id }
    public let schemaVersion: Int
    public let bridgeID: UUID
    public let request: SecretRequest
    public let requestNonce: Data
    public var signature: Data

    public init(
        schemaVersion: Int = Self.currentSchemaVersion,
        bridgeID: UUID,
        request: SecretRequest,
        requestNonce: Data,
        signature: Data = Data()
    ) throws {
        self.schemaVersion = schemaVersion
        self.bridgeID = bridgeID
        self.request = request
        self.requestNonce = requestNonce
        self.signature = signature
        try validateUnsigned(at: request.createdAt)
    }

    public func validate(at date: Date = Date()) throws {
        try validateUnsigned(at: date)
        guard signature.count == BridgeProtocolLimits.signatureBytes else {
            throw BridgeProtocolError.invalidSignature
        }
        try request.validate(at: date)
    }

    public func signingPayload() throws -> Data {
        try validateUnsigned(at: request.createdAt)
        var data = Data()
        data.bridgeAppendField("KeyCourier.Bridge.SignedRequest.v1")
        data.bridgeAppendField(bridgeID)
        data.bridgeAppendField(try BridgeCrypto.requestDigest(for: request))
        data.bridgeAppendField(requestNonce)
        return data
    }

    public func digest() throws -> Data {
        Data(SHA256.hash(data: try signingPayload()))
    }

    private func validateUnsigned(at date: Date) throws {
        guard schemaVersion == Self.currentSchemaVersion,
              requestNonce.count == BridgeProtocolLimits.nonceBytes else {
            throw BridgeProtocolError.invalidRecord
        }
        do {
            try request.validate(at: date)
        } catch KeyCourierError.expiredRequest {
            throw BridgeProtocolError.expired
        } catch {
            throw BridgeProtocolError.invalidRecord
        }
    }
}

public enum BridgeOwnerAction: String, Codable, Sendable {
    case deliver
    case deny
}

public struct BridgeDeliveryCommand: Codable, Sendable, Equatable, Identifiable {
    public static let currentSchemaVersion = BridgeProtocolLimits.schemaVersion

    public let schemaVersion: Int
    public let commandID: UUID
    public let bridgeID: UUID
    public let requestID: UUID
    public let requestDigest: Data
    public let targetID: TargetID
    public let consumerID: ConsumerID
    public let action: BridgeOwnerAction
    public let ephemeralPublicKey: Data?
    public let ciphertext: Data?
    public let createdAt: Date
    public let expiresAt: Date
    public var signature: Data

    public var id: UUID { commandID }

    public init(
        schemaVersion: Int = Self.currentSchemaVersion,
        commandID: UUID = UUID(),
        bridgeID: UUID,
        requestID: UUID,
        requestDigest: Data,
        targetID: TargetID,
        consumerID: ConsumerID,
        action: BridgeOwnerAction,
        ephemeralPublicKey: Data? = nil,
        ciphertext: Data? = nil,
        createdAt: Date = Date(),
        expiresAt: Date,
        signature: Data = Data()
    ) throws {
        self.schemaVersion = schemaVersion
        self.commandID = commandID
        self.bridgeID = bridgeID
        self.requestID = requestID
        self.requestDigest = requestDigest
        self.targetID = targetID
        self.consumerID = consumerID
        self.action = action
        self.ephemeralPublicKey = ephemeralPublicKey
        self.ciphertext = ciphertext
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.signature = signature
        try validateUnsigned(at: createdAt)
    }

    public func validate(at date: Date = Date()) throws {
        try validateUnsigned(at: date)
        guard signature.count == BridgeProtocolLimits.signatureBytes else {
            throw BridgeProtocolError.invalidSignature
        }
        guard date <= expiresAt else { throw BridgeProtocolError.expired }
    }

    public func signingPayload() throws -> Data {
        try validateUnsigned(at: createdAt)
        var data = Data()
        data.bridgeAppendField("KeyCourier.Bridge.DeliveryCommand.v1")
        data.bridgeAppendField(commandID)
        data.bridgeAppendField(bridgeID)
        data.bridgeAppendField(requestID)
        data.bridgeAppendField(requestDigest)
        data.bridgeAppendField(targetID.rawValue)
        data.bridgeAppendField(consumerID.rawValue)
        data.bridgeAppendField(action.rawValue)
        data.bridgeAppendField(ephemeralPublicKey ?? Data())
        data.bridgeAppendField(ciphertext ?? Data())
        data.bridgeAppendInteger(try BridgeDate.milliseconds(createdAt))
        data.bridgeAppendInteger(try BridgeDate.milliseconds(expiresAt))
        return data
    }

    public func digest() throws -> Data {
        Data(SHA256.hash(data: try signingPayload()))
    }

    private func validateUnsigned(at date: Date) throws {
        guard schemaVersion == Self.currentSchemaVersion,
              requestDigest.count == SHA256.byteCount,
              (try? BridgeDate.milliseconds(createdAt)) != nil,
              (try? BridgeDate.milliseconds(expiresAt)) != nil else {
            throw BridgeProtocolError.invalidRecord
        }
        _ = try TargetID(validating: targetID.rawValue)
        _ = try ConsumerID(validating: consumerID.rawValue)
        let duration = expiresAt.timeIntervalSince(createdAt)
        guard duration > 0, duration <= BridgeProtocolLimits.maximumLifetime else {
            throw BridgeProtocolError.invalidRecord
        }
        guard createdAt <= date.addingTimeInterval(BridgeProtocolLimits.futureSkew) else {
            throw BridgeProtocolError.invalidRecord
        }
        switch action {
        case .deny:
            guard ephemeralPublicKey == nil, ciphertext == nil else {
                throw BridgeProtocolError.invalidRecord
            }
        case .deliver:
            guard let ephemeralPublicKey,
                  ephemeralPublicKey.count == BridgeProtocolLimits.keyBytes,
                  (try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephemeralPublicKey)) != nil,
                  let ciphertext,
                  ciphertext.count >= 12 + 16,
                  ciphertext.count <= BridgeProtocolLimits.maximumCiphertextBytes else {
                throw BridgeProtocolError.invalidRecord
            }
        }
    }
}

public struct SignedBridgeReceipt: Codable, Sendable, Equatable, Identifiable {
    public static let currentSchemaVersion = BridgeProtocolLimits.schemaVersion

    public let schemaVersion: Int
    public let bridgeID: UUID
    public let commandID: UUID
    public let requestDigest: Data
    public let receipt: RequestReceipt
    public var signature: Data

    public var id: UUID { commandID }

    public init(
        schemaVersion: Int = Self.currentSchemaVersion,
        bridgeID: UUID,
        commandID: UUID,
        requestDigest: Data,
        receipt: RequestReceipt,
        signature: Data = Data()
    ) throws {
        self.schemaVersion = schemaVersion
        self.bridgeID = bridgeID
        self.commandID = commandID
        self.requestDigest = requestDigest
        self.receipt = receipt
        self.signature = signature
        try validateUnsigned()
    }

    public func validate() throws {
        try validateUnsigned()
        guard signature.count == BridgeProtocolLimits.signatureBytes else {
            throw BridgeProtocolError.invalidSignature
        }
    }

    public func signingPayload() throws -> Data {
        try validateUnsigned()
        var data = Data()
        data.bridgeAppendField("KeyCourier.Bridge.SignedReceipt.v1")
        data.bridgeAppendField(bridgeID)
        data.bridgeAppendField(commandID)
        data.bridgeAppendField(requestDigest)
        data.bridgeAppendField(receipt.requestID)
        data.bridgeAppendField(receipt.status.rawValue)
        data.bridgeAppendField(receipt.targetID.rawValue)
        data.bridgeAppendField(receipt.consumerID.rawValue)
        data.bridgeAppendField(receipt.code.rawValue)
        data.bridgeAppendInteger(try BridgeDate.milliseconds(receipt.recordedAt))
        return data
    }

    public func digest() throws -> Data {
        Data(SHA256.hash(data: try signingPayload()))
    }

    private func validateUnsigned() throws {
        guard schemaVersion == Self.currentSchemaVersion,
              requestDigest.count == SHA256.byteCount,
              receipt.schemaVersion == SecretRequest.currentSchemaVersion,
              receipt.requestID != BridgeProtocolLimits.zeroUUID,
              (try? BridgeDate.milliseconds(receipt.recordedAt)) != nil else {
            throw BridgeProtocolError.invalidRecord
        }
        _ = try TargetID(validating: receipt.targetID.rawValue)
        _ = try ConsumerID(validating: receipt.consumerID.rawValue)
    }
}

public protocol BridgeCallerServing: Sendable {
    func submit(_ request: SecretRequest) throws -> UUID
    func receipt(for requestID: UUID) throws -> RequestReceipt?
}

public protocol BridgeOwnerServing: Sendable {
    func registrations() throws -> [BridgeRegistration]
    func pair(_ registration: BridgeRegistration) throws -> BridgePairingProposal
    func trust(_ grant: BridgeTrustGrant) throws
    func pendingRequests() throws -> [SignedBridgeRequest]
    func enqueue(_ command: BridgeDeliveryCommand) throws
    func receipts() throws -> [SignedBridgeReceipt]
}

public enum BridgeClaimResult: Equatable, Sendable {
    case claimed
    case alreadyClaimed
}

public enum BridgeCrypto {
    private static let sealingSalt = Data("KeyCourier.Bridge.Seal.v1".utf8)
    private static let requestDomain = "KeyCourier.Bridge.Request.v1"

    public static func generatePrivateKeys() -> BridgePrivateKeys {
        try! BridgePrivateKeys(
            signingPrivateKey: Curve25519.Signing.PrivateKey().rawRepresentation,
            keyAgreementPrivateKey: Curve25519.KeyAgreement.PrivateKey().rawRepresentation
        )
    }

    public static func registration(
        bridgeID: UUID,
        displayName: String,
        keys: BridgePrivateKeys,
        bridgeNonce: Data = randomNonce(),
        createdAt: Date = Date(),
        expiresAt: Date? = nil
    ) throws -> BridgeRegistration {
        let signingKey = try signingPrivateKey(keys.signingPrivateKey)
        let agreementKey = try agreementPrivateKey(keys.keyAgreementPrivateKey)
        return try BridgeRegistration(
            bridgeID: bridgeID,
            displayName: displayName,
            signingPublicKey: signingKey.publicKey.rawRepresentation,
            keyAgreementPublicKey: agreementKey.publicKey.rawRepresentation,
            bridgeNonce: bridgeNonce,
            createdAt: createdAt,
            expiresAt: expiresAt
        )
    }

    public static func pairingProposal(
        for registration: BridgeRegistration,
        appSigningPrivateKey: Data,
        appNonce: Data = randomNonce(),
        createdAt: Date = Date(),
        expiresAt: Date? = nil
    ) throws -> BridgePairingProposal {
        let appKey = try signingPrivateKey(appSigningPrivateKey)
        return try BridgePairingProposal(
            bridgeID: registration.bridgeID,
            registrationDigest: try registration.digest(),
            appSigningPublicKey: appKey.publicKey.rawRepresentation,
            appNonce: appNonce,
            createdAt: createdAt,
            expiresAt: expiresAt
        )
    }

    public static func trustGrant(
        for registration: BridgeRegistration,
        proposal: BridgePairingProposal,
        appSigningPrivateKey: Data,
        grantedAt: Date = Date()
    ) throws -> BridgeTrustGrant {
        guard proposal.bridgeID == registration.bridgeID,
              proposal.registrationDigest == (try registration.digest()) else {
            throw BridgeProtocolError.invalidRecord
        }
        let grant = try BridgeTrustGrant(
            bridgeID: registration.bridgeID,
            registrationDigest: try registration.digest(),
            proposalDigest: try proposal.digest(),
            grantedAt: grantedAt
        )
        return try sign(grant, privateKey: appSigningPrivateKey)
    }

    public static func pairingCode(
        registration: BridgeRegistration,
        proposal: BridgePairingProposal,
        at date: Date = Date()
    ) throws -> String {
        try registration.validate(at: date)
        try proposal.validate(at: date)
        guard proposal.bridgeID == registration.bridgeID,
              proposal.registrationDigest == (try registration.digest()) else {
            throw BridgeProtocolError.invalidRecord
        }
        var input = Data()
        input.bridgeAppendField("KeyCourier.Bridge.Pairing.v1")
        input.bridgeAppendField(registration.signingPublicKey)
        input.bridgeAppendField(registration.keyAgreementPublicKey)
        input.bridgeAppendField(registration.bridgeNonce)
        input.bridgeAppendField(proposal.appSigningPublicKey)
        input.bridgeAppendField(proposal.appNonce)
        input.bridgeAppendField(try registration.digest())
        input.bridgeAppendField(try proposal.digest())
        let hex = SHA256.hash(data: input).prefix(6).map { String(format: "%02X", $0) }.joined()
        return stride(from: 0, to: hex.count, by: 4).map { start in
            let lower = hex.index(hex.startIndex, offsetBy: start)
            let upper = hex.index(lower, offsetBy: min(4, hex.count - start))
            return String(hex[lower..<upper])
        }.joined(separator: "-")
    }

    public static func requestDigest(for request: SecretRequest) throws -> Data {
        try request.validate(at: request.createdAt)
        var data = Data()
        data.bridgeAppendField(requestDomain)
        data.bridgeAppendField(request.id)
        data.bridgeAppendField(request.client.rawValue)
        data.bridgeAppendField(request.action.rawValue)
        data.bridgeAppendField(request.secretID.rawValue)
        data.bridgeAppendField(request.targetID.rawValue)
        data.bridgeAppendField(request.consumerID.rawValue)
        data.bridgeAppendField(request.reason)
        data.bridgeAppendInteger(try BridgeDate.milliseconds(request.createdAt))
        data.bridgeAppendInteger(try BridgeDate.milliseconds(request.expiresAt))
        return Data(SHA256.hash(data: data))
    }

    public static func sign(_ registration: BridgeRegistration, privateKey: Data) throws -> BridgeRegistration {
        var signed = registration
        signed.signature = try signingPrivateKey(privateKey).signature(for: registration.signingPayload())
        return signed
    }

    public static func verify(_ registration: BridgeRegistration, at date: Date = Date()) throws {
        try registration.validate(at: date)
        try verifySignature(registration.signature, payload: registration.signingPayload(), publicKey: registration.signingPublicKey)
    }

    public static func sign(_ proposal: BridgePairingProposal, privateKey: Data) throws -> BridgePairingProposal {
        var signed = proposal
        signed.signature = try signingPrivateKey(privateKey).signature(for: proposal.signingPayload())
        return signed
    }

    public static func verify(_ proposal: BridgePairingProposal, at date: Date = Date()) throws {
        try proposal.validate(at: date)
        try verifySignature(proposal.signature, payload: proposal.signingPayload(), publicKey: proposal.appSigningPublicKey)
    }

    public static func sign(_ grant: BridgeTrustGrant, privateKey: Data) throws -> BridgeTrustGrant {
        var signed = grant
        signed.signature = try signingPrivateKey(privateKey).signature(for: grant.signingPayload())
        return signed
    }

    public static func verify(
        _ grant: BridgeTrustGrant,
        appSigningPublicKey: Data,
        at date: Date = Date()
    ) throws {
        try grant.validate(at: date)
        try verifySignature(grant.signature, payload: grant.signingPayload(), publicKey: appSigningPublicKey)
    }

    public static func trustRevocation(
        bridgeID: UUID,
        registrationDigest: Data,
        appSigningPrivateKey: Data,
        revokedAt: Date = Date()
    ) throws -> BridgeTrustRevocation {
        let revocation = try BridgeTrustRevocation(
            bridgeID: bridgeID,
            registrationDigest: registrationDigest,
            revokedAt: revokedAt
        )
        return try sign(revocation, privateKey: appSigningPrivateKey)
    }

    public static func sign(
        _ revocation: BridgeTrustRevocation,
        privateKey: Data
    ) throws -> BridgeTrustRevocation {
        var signed = revocation
        signed.signature = try signingPrivateKey(privateKey).signature(for: revocation.signingPayload())
        return signed
    }

    public static func verify(
        _ revocation: BridgeTrustRevocation,
        signingPublicKey: Data,
        expectedBridgeID: UUID? = nil,
        expectedRegistrationDigest: Data? = nil,
        at date: Date = Date()
    ) throws {
        try revocation.validate(at: date)
        if let expectedBridgeID, revocation.bridgeID != expectedBridgeID {
            throw BridgeProtocolError.invalidRecord
        }
        if let expectedRegistrationDigest,
           revocation.registrationDigest != expectedRegistrationDigest {
            throw BridgeProtocolError.invalidRecord
        }
        try verifySignature(
            revocation.signature,
            payload: revocation.signingPayload(),
            publicKey: signingPublicKey
        )
    }

    public static func sign(_ request: SignedBridgeRequest, privateKey: Data) throws -> SignedBridgeRequest {
        var signed = request
        signed.signature = try signingPrivateKey(privateKey).signature(for: request.signingPayload())
        return signed
    }

    public static func verify(
        _ request: SignedBridgeRequest,
        signingPublicKey: Data,
        expectedBridgeID: UUID? = nil,
        at date: Date = Date()
    ) throws {
        try request.validate(at: date)
        if let expectedBridgeID, request.bridgeID != expectedBridgeID {
            throw BridgeProtocolError.invalidRecord
        }
        try verifySignature(request.signature, payload: request.signingPayload(), publicKey: signingPublicKey)
    }

    public static func sign(_ command: BridgeDeliveryCommand, privateKey: Data) throws -> BridgeDeliveryCommand {
        var signed = command
        signed.signature = try signingPrivateKey(privateKey).signature(for: command.signingPayload())
        return signed
    }

    public static func verify(
        _ command: BridgeDeliveryCommand,
        appSigningPublicKey: Data,
        expectedBridgeID: UUID? = nil,
        expectedRequestDigest: Data? = nil,
        at date: Date = Date()
    ) throws {
        try command.validate(at: date)
        if let expectedBridgeID, command.bridgeID != expectedBridgeID {
            throw BridgeProtocolError.invalidRecord
        }
        if let expectedRequestDigest, command.requestDigest != expectedRequestDigest {
            throw BridgeProtocolError.invalidRecord
        }
        try verifySignature(command.signature, payload: command.signingPayload(), publicKey: appSigningPublicKey)
    }

    public static func sign(_ receipt: SignedBridgeReceipt, privateKey: Data) throws -> SignedBridgeReceipt {
        var signed = receipt
        signed.signature = try signingPrivateKey(privateKey).signature(for: receipt.signingPayload())
        return signed
    }

    public static func verify(
        _ receipt: SignedBridgeReceipt,
        signingPublicKey: Data,
        expectedBridgeID: UUID? = nil,
        expectedCommandID: UUID? = nil,
        expectedRequestID: UUID? = nil,
        expectedRequestDigest: Data? = nil
    ) throws {
        try receipt.validate()
        if let expectedBridgeID, receipt.bridgeID != expectedBridgeID {
            throw BridgeProtocolError.invalidRecord
        }
        if let expectedCommandID, receipt.commandID != expectedCommandID {
            throw BridgeProtocolError.invalidRecord
        }
        if let expectedRequestID, receipt.receipt.requestID != expectedRequestID {
            throw BridgeProtocolError.invalidRecord
        }
        if let expectedRequestDigest, receipt.requestDigest != expectedRequestDigest {
            throw BridgeProtocolError.invalidRecord
        }
        try verifySignature(receipt.signature, payload: receipt.signingPayload(), publicKey: signingPublicKey)
    }

    public static func makeDeliveryCommand(
        request: SecretRequest,
        bridgeID: UUID,
        recipientPublicKey: Data,
        secret: Data,
        appSigningPrivateKey: Data,
        commandID: UUID = UUID(),
        createdAt: Date = Date(),
        expiresAt: Date? = nil
    ) throws -> BridgeDeliveryCommand {
        guard !secret.isEmpty, secret.count <= BridgeProtocolLimits.maximumSecretBytes else {
            throw BridgeProtocolError.invalidRecord
        }
        let requestDigest = try requestDigest(for: request)
        let expiry = expiresAt ?? request.expiresAt
        guard createdAt <= expiry, expiry <= request.expiresAt else {
            throw BridgeProtocolError.invalidRecord
        }
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let recipient = try agreementPublicKey(recipientPublicKey)
        let sharedSecret = try ephemeral.sharedSecretFromKeyAgreement(with: recipient)
        let key = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: sealingSalt,
            sharedInfo: try sealInfo(
                commandID: commandID,
                bridgeID: bridgeID,
                requestDigest: requestDigest,
                targetID: request.targetID,
                consumerID: request.consumerID,
                expiresAt: expiry
            ),
            outputByteCount: 32
        )
        let sealed = try ChaChaPoly.seal(
            secret,
            using: key,
            authenticating: try sealInfo(
                commandID: commandID,
                bridgeID: bridgeID,
                requestDigest: requestDigest,
                targetID: request.targetID,
                consumerID: request.consumerID,
                expiresAt: expiry
            )
        )
        let command = try BridgeDeliveryCommand(
            commandID: commandID,
            bridgeID: bridgeID,
            requestID: request.id,
            requestDigest: requestDigest,
            targetID: request.targetID,
            consumerID: request.consumerID,
            action: .deliver,
            ephemeralPublicKey: ephemeral.publicKey.rawRepresentation,
            ciphertext: sealed.combined,
            createdAt: createdAt,
            expiresAt: expiry
        )
        return try sign(command, privateKey: appSigningPrivateKey)
    }

    public static func makeDenyCommand(
        request: SecretRequest,
        bridgeID: UUID,
        appSigningPrivateKey: Data,
        commandID: UUID = UUID(),
        createdAt: Date = Date(),
        expiresAt: Date? = nil
    ) throws -> BridgeDeliveryCommand {
        let expiry = expiresAt ?? request.expiresAt
        guard createdAt <= expiry, expiry <= request.expiresAt else {
            throw BridgeProtocolError.invalidRecord
        }
        let command = try BridgeDeliveryCommand(
            commandID: commandID,
            bridgeID: bridgeID,
            requestID: request.id,
            requestDigest: try requestDigest(for: request),
            targetID: request.targetID,
            consumerID: request.consumerID,
            action: .deny,
            createdAt: createdAt,
            expiresAt: expiry
        )
        return try sign(command, privateKey: appSigningPrivateKey)
    }

    public static func openDeliveryCommand(
        _ command: BridgeDeliveryCommand,
        recipientPrivateKey: Data,
        appSigningPublicKey: Data,
        expectedBridgeID: UUID,
        expectedRequestDigest: Data,
        at date: Date = Date()
    ) throws -> Data {
        try verify(
            command,
            appSigningPublicKey: appSigningPublicKey,
            expectedBridgeID: expectedBridgeID,
            expectedRequestDigest: expectedRequestDigest,
            at: date
        )
        guard command.action == .deliver,
              let ephemeralPublicKey = command.ephemeralPublicKey,
              let ciphertext = command.ciphertext else {
            throw BridgeProtocolError.invalidRecord
        }
        do {
            let recipient = try agreementPrivateKey(recipientPrivateKey)
            let ephemeral = try agreementPublicKey(ephemeralPublicKey)
            let sharedSecret = try recipient.sharedSecretFromKeyAgreement(with: ephemeral)
            let info = try sealInfo(
                commandID: command.commandID,
                bridgeID: command.bridgeID,
                requestDigest: command.requestDigest,
                targetID: command.targetID,
                consumerID: command.consumerID,
                expiresAt: command.expiresAt
            )
            let key = sharedSecret.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: sealingSalt,
                sharedInfo: info,
                outputByteCount: 32
            )
            let plaintext = try ChaChaPoly.open(
                try ChaChaPoly.SealedBox(combined: ciphertext),
                using: key,
                authenticating: info
            )
            guard !plaintext.isEmpty, plaintext.count <= BridgeProtocolLimits.maximumSecretBytes else {
                throw BridgeProtocolError.invalidRecord
            }
            return plaintext
        } catch let error as BridgeProtocolError {
            throw error
        } catch {
            throw BridgeProtocolError.decryptionFailed
        }
    }

    private static func verifySignature(_ signature: Data, payload: Data, publicKey: Data) throws {
        guard signature.count == BridgeProtocolLimits.signatureBytes else {
            throw BridgeProtocolError.invalidSignature
        }
        do {
            let key = try Curve25519.Signing.PublicKey(rawRepresentation: publicKey)
            guard key.isValidSignature(signature, for: payload) else {
                throw BridgeProtocolError.invalidSignature
            }
        } catch let error as BridgeProtocolError {
            throw error
        } catch {
            throw BridgeProtocolError.invalidKey
        }
    }

    private static func signingPrivateKey(_ data: Data) throws -> Curve25519.Signing.PrivateKey {
        do { return try Curve25519.Signing.PrivateKey(rawRepresentation: data) }
        catch { throw BridgeProtocolError.invalidKey }
    }

    private static func agreementPrivateKey(_ data: Data) throws -> Curve25519.KeyAgreement.PrivateKey {
        do { return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: data) }
        catch { throw BridgeProtocolError.invalidKey }
    }

    private static func agreementPublicKey(_ data: Data) throws -> Curve25519.KeyAgreement.PublicKey {
        do { return try Curve25519.KeyAgreement.PublicKey(rawRepresentation: data) }
        catch { throw BridgeProtocolError.invalidKey }
    }

    public static func randomNonce() -> Data {
        Data((0..<BridgeProtocolLimits.nonceBytes).map { _ in UInt8.random(in: .min ... .max) })
    }

    private static func sealInfo(
        commandID: UUID,
        bridgeID: UUID,
        requestDigest: Data,
        targetID: TargetID,
        consumerID: ConsumerID,
        expiresAt: Date
    ) throws -> Data {
        var data = Data()
        data.bridgeAppendField("KeyCourier.Bridge.DeliveryPayload.v1")
        data.bridgeAppendField(commandID)
        data.bridgeAppendField(bridgeID)
        data.bridgeAppendField(requestDigest)
        data.bridgeAppendField(targetID.rawValue)
        data.bridgeAppendField(consumerID.rawValue)
        data.bridgeAppendInteger(try BridgeDate.milliseconds(expiresAt))
        return data
    }
}

private enum BridgeDate {
    // Keep conversion total for hostile finite Date values. This still covers
    // all practical KeyCourier record lifetimes by a very wide margin.
    private static let maximumSeconds: TimeInterval = 9_000_000_000_000

    static func milliseconds(_ date: Date) throws -> Int64 {
        let seconds = date.timeIntervalSince1970
        guard seconds.isFinite, abs(seconds) <= maximumSeconds else {
            throw BridgeProtocolError.invalidRecord
        }
        let milliseconds = seconds * 1_000
        guard milliseconds.isFinite,
              milliseconds > -9_000_000_000_000_000,
              milliseconds < 9_000_000_000_000_000 else {
            throw BridgeProtocolError.invalidRecord
        }
        return Int64(milliseconds.rounded())
    }
}

private extension Data {
    mutating func bridgeAppendField(_ value: String) {
        bridgeAppendField(Data(value.utf8))
    }

    mutating func bridgeAppendField(_ value: UUID) {
        bridgeAppendField(Data(value.uuidString.lowercased().utf8))
    }

    mutating func bridgeAppendField(_ value: Data) {
        bridgeAppendInteger(Int64(value.count))
        append(value)
    }

    mutating func bridgeAppendInteger(_ value: Int64) {
        var bigEndian = value.bigEndian
        Swift.withUnsafeBytes(of: &bigEndian) { append(contentsOf: $0) }
    }
}

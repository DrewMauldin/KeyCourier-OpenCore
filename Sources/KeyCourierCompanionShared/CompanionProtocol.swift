import CryptoKit
import Foundation

public enum CompanionProtocolError: Error, Equatable, LocalizedError {
    case invalidRecord
    case invalidSignature
    case expired
    case decryptionFailed
    case cloudUnavailable
    case deviceNotPaired

    public var errorDescription: String? {
        switch self {
        case .invalidRecord: "The companion data is invalid."
        case .invalidSignature: "The companion action could not be verified."
        case .expired: "The companion action has expired."
        case .decryptionFailed: "The encrypted credential could not be opened."
        case .cloudUnavailable: "KeyCourier Companion needs an available iCloud account."
        case .deviceNotPaired: "Pair this iPhone with KeyCourier on the Mac first."
        }
    }
}

public enum CompanionRegistrationStatus: String, Codable, Sendable {
    case pending
    case approved
    case denied
}

public struct CompanionDeviceRegistration: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let deviceName: String
    public let signingPublicKey: Data
    public let keyAgreementPublicKey: Data
    public let createdAt: Date
    public var status: CompanionRegistrationStatus
    public var macKeyAgreementPublicKey: Data?
    public var macSigningPublicKey: Data?

    public init(
        id: UUID,
        deviceName: String,
        signingPublicKey: Data,
        keyAgreementPublicKey: Data,
        createdAt: Date = Date(),
        status: CompanionRegistrationStatus = .pending,
        macKeyAgreementPublicKey: Data? = nil,
        macSigningPublicKey: Data? = nil
    ) throws {
        let name = deviceName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty,
              name.count <= 80,
              name.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }),
              signingPublicKey.count == 32,
              keyAgreementPublicKey.count == 32,
              macKeyAgreementPublicKey.map({ $0.count == 32 }) ?? true,
              macSigningPublicKey.map({ $0.count == 32 }) ?? true else {
            throw CompanionProtocolError.invalidRecord
        }
        self.id = id
        self.deviceName = name
        self.signingPublicKey = signingPublicKey
        self.keyAgreementPublicKey = keyAgreementPublicKey
        self.createdAt = createdAt
        self.status = status
        self.macKeyAgreementPublicKey = macKeyAgreementPublicKey
        self.macSigningPublicKey = macSigningPublicKey
    }

    public func validated() throws -> Self {
        try Self(
            id: id,
            deviceName: deviceName,
            signingPublicKey: signingPublicKey,
            keyAgreementPublicKey: keyAgreementPublicKey,
            createdAt: createdAt,
            status: status,
            macKeyAgreementPublicKey: macKeyAgreementPublicKey,
            macSigningPublicKey: macSigningPublicKey
        )
    }
}

public struct CompanionRequestSummary: Codable, Equatable, Identifiable, Sendable {
    public var id: UUID { requestID }
    public let requestID: UUID
    public let clientName: String
    public let credentialName: String
    public let destinationName: String
    public let reason: String
    public let createdAt: Date
    public let expiresAt: Date
    public var signature: Data

    public init(
        requestID: UUID,
        clientName: String,
        credentialName: String,
        destinationName: String,
        reason: String,
        createdAt: Date,
        expiresAt: Date,
        signature: Data = Data()
    ) throws {
        self.requestID = requestID
        self.clientName = try Self.label(clientName, maximum: 40)
        self.credentialName = try Self.label(credentialName, maximum: 80)
        self.destinationName = try Self.label(destinationName, maximum: 80)
        self.reason = try Self.label(reason, maximum: 240)
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.signature = signature
        try validateDates(at: createdAt)
    }

    public func validate(at date: Date = Date()) throws {
        try validateDates(at: date)
        guard signature.count == 64 else { throw CompanionProtocolError.invalidSignature }
    }

    public func digest() throws -> Data {
        Data(SHA256.hash(data: try signingPayload()))
    }

    public func signingPayload() throws -> Data {
        try validateDates(at: createdAt)
        var data = Data("KeyCourier.CompanionRequest.v1".utf8)
        data.appendField(requestID.uuidString.lowercased())
        data.appendField(clientName)
        data.appendField(credentialName)
        data.appendField(destinationName)
        data.appendField(reason)
        data.appendInteger(createdAt.millisecondsSince1970)
        data.appendInteger(expiresAt.millisecondsSince1970)
        return data
    }

    private func validateDates(at date: Date) throws {
        let duration = expiresAt.timeIntervalSince(createdAt)
        guard duration > 0,
              duration <= 24 * 60 * 60,
              createdAt <= date.addingTimeInterval(5 * 60) else {
            throw CompanionProtocolError.invalidRecord
        }
        guard date <= expiresAt else { throw CompanionProtocolError.expired }
    }

    private static func label(_ value: String, maximum: Int) throws -> String {
        let value = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty,
              value.count <= maximum,
              value.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            throw CompanionProtocolError.invalidRecord
        }
        return value
    }
}

public enum CompanionDecisionAction: String, Codable, Sendable {
    case approve
    case deny
}

public enum CompanionCredentialMaterialKind: String, Codable, Equatable, Sendable {
    case single
    case usernamePassword
}

public struct CompanionCredentialSummary: Codable, Equatable, Identifiable, Sendable {
    public var id: String { secretID }
    public let secretID: String
    public let displayName: String
    public let kind: String
    public let materialKind: CompanionCredentialMaterialKind

    public init(
        secretID: String,
        displayName: String,
        kind: String,
        materialKind: CompanionCredentialMaterialKind = .single
    ) throws {
        guard CompanionSecretPayload.isIdentifier(secretID) else {
            throw CompanionProtocolError.invalidRecord
        }
        self.secretID = secretID
        self.displayName = try CompanionSecretPayload.label(displayName)
        self.kind = try CompanionSecretPayload.label(kind)
        self.materialKind = materialKind
    }

    public func validated() throws -> Self {
        try Self(
            secretID: secretID,
            displayName: displayName,
            kind: kind,
            materialKind: materialKind
        )
    }

    private enum CodingKeys: String, CodingKey {
        case secretID
        case displayName
        case kind
        case materialKind
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let materialKind: CompanionCredentialMaterialKind
        if let rawValue = try container.decodeIfPresent(String.self, forKey: .materialKind) {
            guard let decoded = CompanionCredentialMaterialKind(rawValue: rawValue) else {
                throw CompanionProtocolError.invalidRecord
            }
            materialKind = decoded
        } else {
            // Records written before materialKind was added are single values.
            materialKind = .single
        }
        try self.init(
            secretID: container.decode(String.self, forKey: .secretID),
            displayName: container.decode(String.self, forKey: .displayName),
            kind: container.decode(String.self, forKey: .kind),
            materialKind: materialKind
        )
    }

    public func encode(to encoder: Encoder) throws {
        let summary = try validated()
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(summary.secretID, forKey: .secretID)
        try container.encode(summary.displayName, forKey: .displayName)
        try container.encode(summary.kind, forKey: .kind)
        try container.encode(summary.materialKind.rawValue, forKey: .materialKind)
    }
}

public struct CompanionDecision: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let requestID: UUID
    public let requestDigest: Data
    public let deviceID: UUID
    public let action: CompanionDecisionAction
    public let createdAt: Date
    public let expiresAt: Date
    public var signature: Data

    public init(
        id: UUID = UUID(),
        requestID: UUID,
        requestDigest: Data,
        deviceID: UUID,
        action: CompanionDecisionAction,
        createdAt: Date = Date(),
        expiresAt: Date? = nil,
        signature: Data = Data()
    ) throws {
        self.id = id
        self.requestID = requestID
        self.requestDigest = requestDigest
        self.deviceID = deviceID
        self.action = action
        self.createdAt = createdAt
        self.expiresAt = expiresAt ?? createdAt.addingTimeInterval(5 * 60)
        self.signature = signature
        try validateDates(at: createdAt)
    }

    public func validate(at date: Date = Date()) throws {
        try validateDates(at: date)
        guard signature.count == 64 else { throw CompanionProtocolError.invalidSignature }
    }

    public func signingPayload() throws -> Data {
        try validateDates(at: createdAt)
        var data = Data("KeyCourier.CompanionDecision.v1".utf8)
        data.appendField(id.uuidString.lowercased())
        data.appendField(requestID.uuidString.lowercased())
        data.appendField(requestDigest)
        data.appendField(deviceID.uuidString.lowercased())
        data.appendField(action.rawValue)
        data.appendInteger(createdAt.millisecondsSince1970)
        data.appendInteger(expiresAt.millisecondsSince1970)
        return data
    }

    private func validateDates(at date: Date) throws {
        let duration = expiresAt.timeIntervalSince(createdAt)
        guard requestDigest.count == SHA256.byteCount,
              duration > 0,
              duration <= 10 * 60,
              createdAt <= date.addingTimeInterval(5 * 60) else {
            throw CompanionProtocolError.invalidRecord
        }
        guard date <= expiresAt else { throw CompanionProtocolError.expired }
    }
}

public enum CompanionCredentialMaterial: Codable, Equatable, Sendable {
    case single(Data)
    case usernamePassword(username: String, password: Data)

    private enum CodingKeys: String, CodingKey {
        case kind
        case value
        case username
        case password
    }

    private enum MaterialKind: String {
        case single
        case usernamePassword
    }

    private struct UsernamePasswordDelivery: Codable {
        let username: String
        let password: String
    }

    private static let maximumValueBytes = 64 * 1024
    private static let maximumUsernameLength = 256

    public func validated() throws -> Self {
        switch self {
        case .single(let value):
            guard !value.isEmpty, value.count <= Self.maximumValueBytes else {
                throw CompanionProtocolError.invalidRecord
            }
            return .single(value)
        case .usernamePassword(let username, let password):
            let username = username.trimmingCharacters(in: .whitespacesAndNewlines)
            guard let passwordText = String(data: password, encoding: .utf8),
                  !passwordText.unicodeScalars.contains(where: { $0.value == 0 }) else {
                throw CompanionProtocolError.invalidRecord
            }
            guard !username.isEmpty,
                  username.count <= Self.maximumUsernameLength,
                  username.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }),
                  !password.isEmpty,
                  password.count <= Self.maximumValueBytes else {
                throw CompanionProtocolError.invalidRecord
            }
            guard try Self.encodeDelivery(username: username, password: password).count
                    <= Self.maximumValueBytes else {
                throw CompanionProtocolError.invalidRecord
            }
            return .usernamePassword(username: username, password: password)
        }
    }

    /// Returns the bytes that the existing single-value Keychain and consumer
    /// paths should store. A pair is represented as compact, sorted JSON so
    /// usernames and passwords cannot be confused by a delimiter or newline.
    public func deliveryData() throws -> Data {
        switch try validated() {
        case .single(let value):
            return value
        case .usernamePassword(let username, let password):
            return try Self.encodeDelivery(username: username, password: password)
        }
    }

    public static func usernamePassword(
        fromDeliveryData data: Data
    ) throws -> (username: String, password: Data) {
        guard data.count <= Self.maximumValueBytes else {
            throw CompanionProtocolError.invalidRecord
        }
        let decoded = try JSONDecoder().decode(UsernamePasswordDelivery.self, from: data)
        let material = try CompanionCredentialMaterial.usernamePassword(
            username: decoded.username,
            password: Data(decoded.password.utf8)
        ).validated()
        guard case .usernamePassword(let username, let password) = material else {
            throw CompanionProtocolError.invalidRecord
        }
        return (username, password)
    }

    public var singleValue: Data? {
        guard case .single(let value) = self else { return nil }
        return value
    }

    public var username: String? {
        guard case .usernamePassword(let username, _) = self else { return nil }
        return username
    }

    public var password: Data? {
        guard case .usernamePassword(_, let password) = self else { return nil }
        return password
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        guard let kind = MaterialKind(rawValue: try container.decode(String.self, forKey: .kind)) else {
            throw CompanionProtocolError.invalidRecord
        }
        switch kind {
        case .single:
            guard !container.contains(.username), !container.contains(.password) else {
                throw CompanionProtocolError.invalidRecord
            }
            self = try CompanionCredentialMaterial.single(
                container.decode(Data.self, forKey: .value)
            ).validated()
        case .usernamePassword:
            guard !container.contains(.value) else {
                throw CompanionProtocolError.invalidRecord
            }
            self = try CompanionCredentialMaterial.usernamePassword(
                username: container.decode(String.self, forKey: .username),
                password: container.decode(Data.self, forKey: .password)
            ).validated()
        }
    }

    public func encode(to encoder: Encoder) throws {
        let material = try validated()
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch material {
        case .single(let value):
            try container.encode(MaterialKind.single.rawValue, forKey: .kind)
            try container.encode(value, forKey: .value)
        case .usernamePassword(let username, let password):
            try container.encode(MaterialKind.usernamePassword.rawValue, forKey: .kind)
            try container.encode(username, forKey: .username)
            try container.encode(password, forKey: .password)
        }
    }

    private static func encodeDelivery(username: String, password: Data) throws -> Data {
        guard let password = String(data: password, encoding: .utf8),
              !password.unicodeScalars.contains(where: { $0.value == 0 }) else {
            throw CompanionProtocolError.invalidRecord
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(
            UsernamePasswordDelivery(username: username, password: password)
        )
    }
}

public struct CompanionSecretPayload: Codable, Equatable, Sendable {
    public let secretID: String
    public let displayName: String
    public let kind: String
    public let material: CompanionCredentialMaterial
    public let ownerName: String?
    public let projectName: String?
    public let environmentName: String?
    public let rotationDueAt: Date?
    public let expiresAt: Date?
    public let replacesExisting: Bool

    /// Kept for single-value callers. Pair payloads return their unambiguous
    /// JSON representation for existing one-value storage and delivery paths.
    public var value: Data {
        (try? material.deliveryData()) ?? Data()
    }

    public var username: String? { material.username }
    public var password: Data? { material.password }

    public init(
        secretID: String,
        displayName: String,
        kind: String,
        value: Data,
        ownerName: String? = nil,
        projectName: String? = nil,
        environmentName: String? = nil,
        rotationDueAt: Date? = nil,
        expiresAt: Date? = nil,
        replacesExisting: Bool = false
    ) throws {
        try self.init(
            secretID: secretID,
            displayName: displayName,
            kind: kind,
            material: .single(value),
            ownerName: ownerName,
            projectName: projectName,
            environmentName: environmentName,
            rotationDueAt: rotationDueAt,
            expiresAt: expiresAt,
            replacesExisting: replacesExisting
        )
    }

    public init(
        secretID: String,
        displayName: String,
        kind: String,
        username: String,
        password: Data,
        ownerName: String? = nil,
        projectName: String? = nil,
        environmentName: String? = nil,
        rotationDueAt: Date? = nil,
        expiresAt: Date? = nil,
        replacesExisting: Bool = false
    ) throws {
        try self.init(
            secretID: secretID,
            displayName: displayName,
            kind: kind,
            material: .usernamePassword(username: username, password: password),
            ownerName: ownerName,
            projectName: projectName,
            environmentName: environmentName,
            rotationDueAt: rotationDueAt,
            expiresAt: expiresAt,
            replacesExisting: replacesExisting
        )
    }

    public init(
        secretID: String,
        displayName: String,
        kind: String,
        material: CompanionCredentialMaterial,
        ownerName: String? = nil,
        projectName: String? = nil,
        environmentName: String? = nil,
        rotationDueAt: Date? = nil,
        expiresAt: Date? = nil,
        replacesExisting: Bool = false
    ) throws {
        guard Self.isIdentifier(secretID) else {
            throw CompanionProtocolError.invalidRecord
        }
        self.secretID = secretID
        self.displayName = try Self.label(displayName)
        self.kind = try Self.label(kind)
        self.material = try material.validated()
        self.ownerName = try Self.optionalLabel(ownerName)
        self.projectName = try Self.optionalLabel(projectName)
        self.environmentName = try Self.optionalLabel(environmentName)
        self.rotationDueAt = rotationDueAt
        self.expiresAt = expiresAt
        self.replacesExisting = replacesExisting
    }

    public func deliveryData() throws -> Data {
        try material.deliveryData()
    }

    public func validated() throws -> Self {
        try Self(
            secretID: secretID,
            displayName: displayName,
            kind: kind,
            material: material,
            ownerName: ownerName,
            projectName: projectName,
            environmentName: environmentName,
            rotationDueAt: rotationDueAt,
            expiresAt: expiresAt,
            replacesExisting: replacesExisting
        )
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let hasValue = container.contains(.value)
        let hasUsername = container.contains(.username)
        let hasPassword = container.contains(.password)
        let hasNestedMaterial = container.contains(.material)
        let value = try container.decodeIfPresent(Data.self, forKey: .value)
        let username = try container.decodeIfPresent(String.self, forKey: .username)
        let password = try container.decodeIfPresent(Data.self, forKey: .password)
        let nestedMaterial = try container.decodeIfPresent(
            CompanionCredentialMaterial.self,
            forKey: .material
        )

        let decodedMaterial: CompanionCredentialMaterial
        if hasNestedMaterial {
            guard let nestedMaterial,
                  !hasValue,
                  !hasUsername,
                  !hasPassword else {
                throw CompanionProtocolError.invalidRecord
            }
            decodedMaterial = nestedMaterial
        } else if hasValue {
            guard let value, !hasUsername, !hasPassword else {
                throw CompanionProtocolError.invalidRecord
            }
            decodedMaterial = .single(value)
        } else if hasUsername || hasPassword {
            guard hasUsername, hasPassword,
                  let username, let password else {
                throw CompanionProtocolError.invalidRecord
            }
            decodedMaterial = .usernamePassword(username: username, password: password)
        } else {
            throw CompanionProtocolError.invalidRecord
        }

        try self.init(
            secretID: container.decode(String.self, forKey: .secretID),
            displayName: container.decode(String.self, forKey: .displayName),
            kind: container.decode(String.self, forKey: .kind),
            material: decodedMaterial,
            ownerName: container.decodeIfPresent(String.self, forKey: .ownerName),
            projectName: container.decodeIfPresent(String.self, forKey: .projectName),
            environmentName: container.decodeIfPresent(String.self, forKey: .environmentName),
            rotationDueAt: container.decodeIfPresent(Date.self, forKey: .rotationDueAt),
            expiresAt: container.decodeIfPresent(Date.self, forKey: .expiresAt),
            replacesExisting: container.decodeIfPresent(Bool.self, forKey: .replacesExisting) ?? false
        )
    }

    public func encode(to encoder: Encoder) throws {
        let payload = try validated()
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(payload.secretID, forKey: .secretID)
        try container.encode(payload.displayName, forKey: .displayName)
        try container.encode(payload.kind, forKey: .kind)
        switch payload.material {
        case .single(let value):
            try container.encode(value, forKey: .value)
        case .usernamePassword(let username, let password):
            try container.encode(username, forKey: .username)
            try container.encode(password, forKey: .password)
        }
        try container.encodeIfPresent(payload.ownerName, forKey: .ownerName)
        try container.encodeIfPresent(payload.projectName, forKey: .projectName)
        try container.encodeIfPresent(payload.environmentName, forKey: .environmentName)
        try container.encodeIfPresent(payload.rotationDueAt, forKey: .rotationDueAt)
        try container.encodeIfPresent(payload.expiresAt, forKey: .expiresAt)
        try container.encode(payload.replacesExisting, forKey: .replacesExisting)
    }

    private enum CodingKeys: String, CodingKey {
        case secretID
        case displayName
        case kind
        case value
        case username
        case password
        case material
        case ownerName
        case projectName
        case environmentName
        case rotationDueAt
        case expiresAt
        case replacesExisting
    }

    fileprivate static func isIdentifier(_ value: String) -> Bool {
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789._-")
        return !value.isEmpty
            && value.count <= 64
            && (value.first?.isLetter == true || value.first?.isNumber == true)
            && value.unicodeScalars.allSatisfy(allowed.contains)
    }

    fileprivate static func label(_ value: String) throws -> String {
        let value = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty,
              value.count <= 80,
              value.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            throw CompanionProtocolError.invalidRecord
        }
        return value
    }

    private static func optionalLabel(_ value: String?) throws -> String? {
        guard let value else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : try label(trimmed)
    }
}

public struct CompanionSecretEnvelope: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let deviceID: UUID
    public let ephemeralPublicKey: Data
    public let ciphertext: Data
    public let createdAt: Date
    public let expiresAt: Date
    public var signature: Data

    public init(
        id: UUID = UUID(),
        deviceID: UUID,
        ephemeralPublicKey: Data,
        ciphertext: Data,
        createdAt: Date = Date(),
        expiresAt: Date? = nil,
        signature: Data = Data()
    ) throws {
        guard ephemeralPublicKey.count == 32,
              !ciphertext.isEmpty,
              ciphertext.count <= 72 * 1024 else {
            throw CompanionProtocolError.invalidRecord
        }
        self.id = id
        self.deviceID = deviceID
        self.ephemeralPublicKey = ephemeralPublicKey
        self.ciphertext = ciphertext
        self.createdAt = createdAt
        self.expiresAt = expiresAt ?? createdAt.addingTimeInterval(15 * 60)
        self.signature = signature
        try validateDates(at: createdAt)
    }

    public func validate(at date: Date = Date()) throws {
        try validateDates(at: date)
        guard ephemeralPublicKey.count == 32,
              !ciphertext.isEmpty,
              ciphertext.count <= 72 * 1024,
              signature.count == 64 else {
            throw CompanionProtocolError.invalidRecord
        }
    }

    public func signingPayload() throws -> Data {
        try validateDates(at: createdAt)
        var data = Data("KeyCourier.CompanionSecretEnvelope.v1".utf8)
        data.appendField(id.uuidString.lowercased())
        data.appendField(deviceID.uuidString.lowercased())
        data.appendField(ephemeralPublicKey)
        data.appendField(ciphertext)
        data.appendInteger(createdAt.millisecondsSince1970)
        data.appendInteger(expiresAt.millisecondsSince1970)
        return data
    }

    private func validateDates(at date: Date) throws {
        let duration = expiresAt.timeIntervalSince(createdAt)
        guard duration > 0,
              duration <= 30 * 60,
              createdAt <= date.addingTimeInterval(5 * 60) else {
            throw CompanionProtocolError.invalidRecord
        }
        guard date <= expiresAt else { throw CompanionProtocolError.expired }
    }
}

public struct CompanionPrivateKeys: Equatable, Sendable {
    public let signingPrivateKey: Data
    public let keyAgreementPrivateKey: Data

    public init(signingPrivateKey: Data, keyAgreementPrivateKey: Data) throws {
        _ = try Curve25519.Signing.PrivateKey(rawRepresentation: signingPrivateKey)
        _ = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: keyAgreementPrivateKey)
        self.signingPrivateKey = signingPrivateKey
        self.keyAgreementPrivateKey = keyAgreementPrivateKey
    }
}

public enum CompanionCrypto {
    private static let salt = Data("KeyCourier.Companion.v1".utf8)

    public static func generatePrivateKeys() -> CompanionPrivateKeys {
        try! CompanionPrivateKeys(
            signingPrivateKey: Curve25519.Signing.PrivateKey().rawRepresentation,
            keyAgreementPrivateKey: Curve25519.KeyAgreement.PrivateKey().rawRepresentation
        )
    }

    public static func registration(
        deviceID: UUID,
        deviceName: String,
        keys: CompanionPrivateKeys,
        createdAt: Date = Date()
    ) throws -> CompanionDeviceRegistration {
        let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: keys.signingPrivateKey)
        let agreementKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: keys.keyAgreementPrivateKey)
        return try CompanionDeviceRegistration(
            id: deviceID,
            deviceName: deviceName,
            signingPublicKey: signingKey.publicKey.rawRepresentation,
            keyAgreementPublicKey: agreementKey.publicKey.rawRepresentation,
            createdAt: createdAt
        )
    }

    public static func pairingCode(for registration: CompanionDeviceRegistration) throws -> String {
        let registration = try registration.validated()
        guard let macPublicKey = registration.macKeyAgreementPublicKey,
              let macSigningPublicKey = registration.macSigningPublicKey else {
            throw CompanionProtocolError.invalidRecord
        }
        var input = Data("KeyCourier.CompanionPairing.v1".utf8)
        input.appendField(registration.id.uuidString.lowercased())
        input.appendField(registration.signingPublicKey)
        input.appendField(registration.keyAgreementPublicKey)
        input.appendField(macPublicKey)
        input.appendField(macSigningPublicKey)
        let prefix = SHA256.hash(data: input).prefix(6)
        let value = prefix.map { String(format: "%02X", $0) }.joined()
        return stride(from: 0, to: value.count, by: 4)
            .map { start in
                let lower = value.index(value.startIndex, offsetBy: start)
                let upper = value.index(lower, offsetBy: min(4, value.count - start))
                return String(value[lower..<upper])
            }
            .joined(separator: "-")
    }

    public static func sign(
        _ summary: CompanionRequestSummary,
        keys: CompanionPrivateKeys
    ) throws -> CompanionRequestSummary {
        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: keys.signingPrivateKey)
        var signed = summary
        signed.signature = try privateKey.signature(for: summary.signingPayload())
        return signed
    }

    public static func verify(
        _ summary: CompanionRequestSummary,
        signingPublicKey: Data,
        at date: Date = Date()
    ) throws {
        try summary.validate(at: date)
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: signingPublicKey)
        guard publicKey.isValidSignature(summary.signature, for: try summary.signingPayload()) else {
            throw CompanionProtocolError.invalidSignature
        }
    }

    public static func sign(
        _ decision: CompanionDecision,
        keys: CompanionPrivateKeys
    ) throws -> CompanionDecision {
        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: keys.signingPrivateKey)
        var signed = decision
        signed.signature = try privateKey.signature(for: decision.signingPayload())
        return signed
    }

    public static func verify(
        _ decision: CompanionDecision,
        signingPublicKey: Data,
        at date: Date = Date()
    ) throws {
        try decision.validate(at: date)
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: signingPublicKey)
        guard publicKey.isValidSignature(decision.signature, for: try decision.signingPayload()) else {
            throw CompanionProtocolError.invalidSignature
        }
    }

    public static func seal(
        _ payload: CompanionSecretPayload,
        deviceID: UUID,
        recipientPublicKey: Data,
        signingKeys: CompanionPrivateKeys,
        createdAt: Date = Date()
    ) throws -> CompanionSecretEnvelope {
        let payload = try payload.validated()
        let envelopeID = UUID()
        let ephemeralKey = Curve25519.KeyAgreement.PrivateKey()
        let recipient = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: recipientPublicKey)
        let sharedSecret = try ephemeralKey.sharedSecretFromKeyAgreement(with: recipient)
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: Data(envelopeID.uuidString.lowercased().utf8),
            outputByteCount: 32
        )
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        encoder.outputFormatting = [.sortedKeys]
        let sealed = try ChaChaPoly.seal(encoder.encode(payload), using: symmetricKey)
        var envelope = try CompanionSecretEnvelope(
            id: envelopeID,
            deviceID: deviceID,
            ephemeralPublicKey: ephemeralKey.publicKey.rawRepresentation,
            ciphertext: sealed.combined,
            createdAt: createdAt
        )
        let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: signingKeys.signingPrivateKey)
        envelope.signature = try signingKey.signature(for: envelope.signingPayload())
        return envelope
    }

    public static func open(
        _ envelope: CompanionSecretEnvelope,
        recipientKeys: CompanionPrivateKeys,
        senderSigningPublicKey: Data,
        at date: Date = Date()
    ) throws -> CompanionSecretPayload {
        try envelope.validate(at: date)
        let signingKey = try Curve25519.Signing.PublicKey(rawRepresentation: senderSigningPublicKey)
        guard signingKey.isValidSignature(envelope.signature, for: try envelope.signingPayload()) else {
            throw CompanionProtocolError.invalidSignature
        }
        do {
            let recipient = try Curve25519.KeyAgreement.PrivateKey(
                rawRepresentation: recipientKeys.keyAgreementPrivateKey
            )
            let ephemeral = try Curve25519.KeyAgreement.PublicKey(
                rawRepresentation: envelope.ephemeralPublicKey
            )
            let sharedSecret = try recipient.sharedSecretFromKeyAgreement(with: ephemeral)
            let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: salt,
                sharedInfo: Data(envelope.id.uuidString.lowercased().utf8),
                outputByteCount: 32
            )
            let box = try ChaChaPoly.SealedBox(combined: envelope.ciphertext)
            let plaintext = try ChaChaPoly.open(box, using: symmetricKey)
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .millisecondsSince1970
            return try decoder.decode(CompanionSecretPayload.self, from: plaintext).validated()
        } catch let error as CompanionProtocolError {
            throw error
        } catch {
            throw CompanionProtocolError.decryptionFailed
        }
    }
}

private extension Date {
    var millisecondsSince1970: Int64 {
        Int64((timeIntervalSince1970 * 1_000).rounded())
    }
}

private extension Data {
    mutating func appendField(_ value: String) {
        appendField(Data(value.utf8))
    }

    mutating func appendField(_ value: Data) {
        appendInteger(Int64(value.count))
        append(value)
    }

    mutating func appendInteger(_ value: Int64) {
        var bigEndian = value.bigEndian
        Swift.withUnsafeBytes(of: &bigEndian) { append(contentsOf: $0) }
    }
}

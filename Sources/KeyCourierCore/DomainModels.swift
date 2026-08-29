import Foundation

public enum KeyCourierError: Error, Equatable, LocalizedError {
    case invalidIdentifier
    case invalidReason
    case unsupportedSchemaVersion
    case invalidExpiry
    case expiredRequest
    case malformedSecretValue
    case malformedDestination
    case unsafeFile
    case unsupportedDestination
    case requestLimitExceeded
    case ageUnavailable
    case ageOperationFailed
    case remotePackageInvalid
    case replayedRequest
    case consumerNotFound
    case targetMismatch
    case requestNotFound
    case invalidMetadata
    case invalidBackup
    case telegramNotConfigured
    case telegramRequestFailed
    case approvalInvalid
    case keychainFailure(Int32)
    case unexpectedKeychainData

    public var errorDescription: String? {
        switch self {
        case .invalidIdentifier: "Use 1 to 64 lowercase letters, numbers, dots, underscores or hyphens."
        case .invalidReason: "Provide a plain-text reason between 1 and 240 characters."
        case .unsupportedSchemaVersion: "This request schema is not supported."
        case .invalidExpiry: "Requests must expire within 24 hours of creation."
        case .expiredRequest: "This request has expired."
        case .malformedSecretValue: "This destination accepts a single-line UTF-8 value without null bytes."
        case .malformedDestination: "The destination configuration is invalid."
        case .unsafeFile: "The destination is not a safe owner-controlled regular file."
        case .unsupportedDestination: "This destination is not available on this device."
        case .requestLimitExceeded: "The request inbox is full; wait for an existing request to be handled."
        case .ageUnavailable: "The age encryption helper is not installed on this device."
        case .ageOperationFailed: "The age encryption helper could not complete the operation."
        case .remotePackageInvalid: "The remote delivery package is invalid."
        case .replayedRequest: "This remote delivery request has already been processed."
        case .consumerNotFound: "The approved consumer profile was not found."
        case .targetMismatch: "The request target does not match the consumer profile."
        case .requestNotFound: "The request was not found."
        case .invalidMetadata: "Check the credential details and try again."
        case .invalidBackup: "The encrypted recovery file is not a valid KeyCourier backup."
        case .telegramNotConfigured: "Finish Telegram approval setup first."
        case .telegramRequestFailed: "Telegram could not complete the approval request."
        case .approvalInvalid: "This approval is unknown, expired or has already been used."
        case .keychainFailure(let status): "The system Keychain operation failed (OSStatus \(status))."
        case .unexpectedKeychainData: "The system Keychain returned unexpected data."
        }
    }
}

private enum IdentifierValidator {
    static func validate(_ value: String) throws -> String {
        guard !value.isEmpty, value.count <= 64 else {
            throw KeyCourierError.invalidIdentifier
        }
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789._-")
        guard value.unicodeScalars.allSatisfy(allowed.contains),
              value.first?.isLetter == true || value.first?.isNumber == true else {
            throw KeyCourierError.invalidIdentifier
        }
        return value
    }
}

public struct SecretID: RawRepresentable, Codable, Hashable, Sendable {
    public let rawValue: String

    public init(validating rawValue: String) throws {
        self.rawValue = try IdentifierValidator.validate(rawValue)
    }

    public init?(rawValue: String) {
        guard let validated = try? IdentifierValidator.validate(rawValue) else { return nil }
        self.rawValue = validated
    }
}

public struct TargetID: RawRepresentable, Codable, Hashable, Sendable {
    public let rawValue: String

    public init(validating rawValue: String) throws {
        self.rawValue = try IdentifierValidator.validate(rawValue)
    }

    public init?(rawValue: String) {
        guard let validated = try? IdentifierValidator.validate(rawValue) else { return nil }
        self.rawValue = validated
    }
}

public struct ConsumerID: RawRepresentable, Codable, Hashable, Sendable {
    public let rawValue: String

    public init(validating rawValue: String) throws {
        self.rawValue = try IdentifierValidator.validate(rawValue)
    }

    public init?(rawValue: String) {
        guard let validated = try? IdentifierValidator.validate(rawValue) else { return nil }
        self.rawValue = validated
    }
}

public enum AgentClient: String, Codable, CaseIterable, Sendable {
    case codex
    case claude
    case opencode
}

public enum RequestAction: String, Codable, Sendable {
    case install
}

public struct SecretRequest: Codable, Equatable, Identifiable, Sendable {
    public static let currentSchemaVersion = 1

    public let schemaVersion: Int
    public let id: UUID
    public let client: AgentClient
    public let action: RequestAction
    public let secretID: SecretID
    public let targetID: TargetID
    public let consumerID: ConsumerID
    public let reason: String
    public let createdAt: Date
    public let expiresAt: Date

    public init(
        schemaVersion: Int = currentSchemaVersion,
        id: UUID = UUID(),
        client: AgentClient,
        action: RequestAction = .install,
        secretID: SecretID,
        targetID: TargetID,
        consumerID: ConsumerID,
        reason: String,
        createdAt: Date = Date(),
        expiresAt: Date? = nil
    ) throws {
        self.schemaVersion = schemaVersion
        self.id = id
        self.client = client
        self.action = action
        self.secretID = secretID
        self.targetID = targetID
        self.consumerID = consumerID
        self.reason = reason.trimmingCharacters(in: .whitespacesAndNewlines)
        self.createdAt = createdAt
        self.expiresAt = expiresAt ?? createdAt.addingTimeInterval(15 * 60)
        try validate(at: createdAt)
    }

    public func validate(at date: Date = Date()) throws {
        guard schemaVersion == Self.currentSchemaVersion else {
            throw KeyCourierError.unsupportedSchemaVersion
        }
        guard !reason.isEmpty,
              reason.count <= 240,
              reason.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            throw KeyCourierError.invalidReason
        }
        let duration = expiresAt.timeIntervalSince(createdAt)
        guard duration > 0, duration <= 24 * 60 * 60 else {
            throw KeyCourierError.invalidExpiry
        }
        guard createdAt <= date.addingTimeInterval(5 * 60) else {
            throw KeyCourierError.invalidExpiry
        }
        guard date <= expiresAt else {
            throw KeyCourierError.expiredRequest
        }
    }
}

public enum ReceiptStatus: String, Codable, Sendable {
    case verified
    case failed
    case offline
    case denied
    case notConfigured
}

public enum ReceiptCode: String, Codable, Sendable {
    case consumerVerified
    case ownerDenied
    case secretMissing
    case secretExpired
    case consumerMissing
    case targetUnavailable
    case validationFailed
    case deliveryFailed
}

public struct RequestReceipt: Codable, Equatable, Identifiable, Sendable {
    public var id: UUID { requestID }

    public let schemaVersion: Int
    public let requestID: UUID
    public let status: ReceiptStatus
    public let targetID: TargetID
    public let consumerID: ConsumerID
    public let code: ReceiptCode
    public let recordedAt: Date

    public init(
        schemaVersion: Int = SecretRequest.currentSchemaVersion,
        requestID: UUID,
        status: ReceiptStatus,
        targetID: TargetID,
        consumerID: ConsumerID,
        code: ReceiptCode,
        recordedAt: Date = Date()
    ) {
        self.schemaVersion = schemaVersion
        self.requestID = requestID
        self.status = status
        self.targetID = targetID
        self.consumerID = consumerID
        self.code = code
        self.recordedAt = recordedAt
    }
}

public enum SecretKind: String, Codable, CaseIterable, Sendable {
    case apiKey
    case password
    case token
    case other

    public var displayName: String {
        switch self {
        case .apiKey: "API key"
        case .password: "Password"
        case .token: "Token"
        case .other: "Other"
        }
    }
}

public enum SecretMaterialKind: String, Codable, CaseIterable, Sendable {
    case single
    case usernamePassword
}

public struct SecretMetadata: Codable, Equatable, Identifiable, Sendable {
    public var id: SecretID { secretID }

    public let secretID: SecretID
    public var displayName: String
    public var kind: SecretKind
    public var materialKind: SecretMaterialKind
    public let createdAt: Date
    public var updatedAt: Date
    public var ownerName: String?
    public var projectName: String?
    public var environmentName: String?
    public var rotationDueAt: Date?
    public var expiresAt: Date?
    public var allowsTelegramApproval: Bool
    public var allowsCompanionApproval: Bool

    public init(
        secretID: SecretID,
        displayName: String,
        kind: SecretKind,
        materialKind: SecretMaterialKind = .single,
        createdAt: Date = Date(),
        updatedAt: Date = Date(),
        ownerName: String? = nil,
        projectName: String? = nil,
        environmentName: String? = nil,
        rotationDueAt: Date? = nil,
        expiresAt: Date? = nil,
        allowsTelegramApproval: Bool = false,
        allowsCompanionApproval: Bool = false
    ) {
        self.secretID = secretID
        self.displayName = displayName
        self.kind = kind
        self.materialKind = materialKind
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.ownerName = ownerName
        self.projectName = projectName
        self.environmentName = environmentName
        self.rotationDueAt = rotationDueAt
        self.expiresAt = expiresAt
        self.allowsTelegramApproval = allowsTelegramApproval
        self.allowsCompanionApproval = allowsCompanionApproval
    }

    private enum CodingKeys: String, CodingKey {
        case secretID
        case displayName
        case kind
        case materialKind
        case createdAt
        case updatedAt
        case ownerName
        case projectName
        case environmentName
        case rotationDueAt
        case expiresAt
        case allowsTelegramApproval
        case allowsCompanionApproval
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        secretID = try container.decode(SecretID.self, forKey: .secretID)
        displayName = try container.decode(String.self, forKey: .displayName)
        kind = try container.decode(SecretKind.self, forKey: .kind)
        materialKind = try container.decodeIfPresent(SecretMaterialKind.self, forKey: .materialKind) ?? .single
        createdAt = try container.decode(Date.self, forKey: .createdAt)
        updatedAt = try container.decode(Date.self, forKey: .updatedAt)
        ownerName = try container.decodeIfPresent(String.self, forKey: .ownerName)
        projectName = try container.decodeIfPresent(String.self, forKey: .projectName)
        environmentName = try container.decodeIfPresent(String.self, forKey: .environmentName)
        rotationDueAt = try container.decodeIfPresent(Date.self, forKey: .rotationDueAt)
        expiresAt = try container.decodeIfPresent(Date.self, forKey: .expiresAt)
        allowsTelegramApproval = try container.decodeIfPresent(Bool.self, forKey: .allowsTelegramApproval) ?? false
        allowsCompanionApproval = try container.decodeIfPresent(Bool.self, forKey: .allowsCompanionApproval) ?? false
    }
}

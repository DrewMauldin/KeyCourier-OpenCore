import Foundation

public enum SecretLifecycleStatus: String, Codable, Equatable, Sendable {
    case expired
    case rotationDue
    case expiringSoon
    case healthy
    case untracked

    public var needsAttention: Bool {
        self == .expired || self == .rotationDue || self == .expiringSoon
    }
}

public extension SecretMetadata {
    func lifecycleStatus(at date: Date = Date()) -> SecretLifecycleStatus {
        if let expiresAt, expiresAt <= date { return .expired }
        if let rotationDueAt, rotationDueAt <= date { return .rotationDue }
        if let expiresAt, expiresAt <= date.addingTimeInterval(14 * 24 * 60 * 60) {
            return .expiringSoon
        }
        if rotationDueAt != nil || expiresAt != nil { return .healthy }
        return .untracked
    }
}

public struct ImportedSecretDraft: Equatable, Sendable {
    public let id: SecretID
    public let displayName: String
    public let value: Data

    public init(id: SecretID, displayName: String, value: Data) {
        self.id = id
        self.displayName = displayName
        self.value = value
    }
}

public enum DotenvSecretImporter {
    private static let maximumBytes = 1024 * 1024

    public static func parse(contentsOf url: URL) throws -> [ImportedSecretDraft] {
        try parse(SecureFileSystem.readRegularFile(url, maximumBytes: maximumBytes))
    }

    public static func parse(_ data: Data) throws -> [ImportedSecretDraft] {
        guard !data.isEmpty, data.count <= maximumBytes,
              let text = String(data: data, encoding: .utf8),
              !text.contains("\0") else {
            throw KeyCourierError.malformedSecretValue
        }

        var drafts: [ImportedSecretDraft] = []
        var seen = Set<SecretID>()
        for rawLine in text.split(whereSeparator: \Character.isNewline) {
            var line = String(rawLine).trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, !line.hasPrefix("#") else { continue }
            if line.hasPrefix("export ") {
                line.removeFirst("export ".count)
            }
            guard let separator = line.firstIndex(of: "=") else {
                throw KeyCourierError.malformedSecretValue
            }
            let variable = String(line[..<separator]).trimmingCharacters(in: .whitespaces)
            var value = String(line[line.index(after: separator)...]).trimmingCharacters(in: .whitespaces)
            guard isEnvironmentVariable(variable) else {
                throw KeyCourierError.malformedSecretValue
            }
            if value.count >= 2,
               let first = value.first,
               let last = value.last,
               (first == "\"" || first == "'"),
               last == first {
                value.removeFirst()
                value.removeLast()
            }
            let secret = Data(value.utf8)
            guard !secret.isEmpty, secret.count <= 64 * 1024 else {
                throw KeyCourierError.malformedSecretValue
            }
            let identifier = try identifier(for: variable)
            guard seen.insert(identifier).inserted else {
                throw KeyCourierError.invalidIdentifier
            }
            let displayName = variable
                .lowercased()
                .split(separator: "_")
                .map { $0.prefix(1).uppercased() + $0.dropFirst() }
                .joined(separator: " ")
            drafts.append(ImportedSecretDraft(id: identifier, displayName: displayName, value: secret))
        }
        guard !drafts.isEmpty, drafts.count <= 200 else {
            throw KeyCourierError.malformedSecretValue
        }
        return drafts
    }

    private static func isEnvironmentVariable(_ value: String) -> Bool {
        guard value.count <= 128,
              value.first.map({ $0 == "_" || $0.isLetter }) == true else { return false }
        return value.allSatisfy { $0 == "_" || $0.isLetter || $0.isNumber }
    }

    private static func identifier(for variable: String) throws -> SecretID {
        var value = variable.lowercased().replacingOccurrences(of: "_", with: "-")
        if value.count > 64 { value = String(value.prefix(64)) }
        return try SecretID(validating: value)
    }
}

public struct RecoveryConfiguration: Codable, Equatable, Sendable {
    public let ageRecipients: [String]

    public init(ageRecipients: [String]) throws {
        self.ageRecipients = try AgeRecipientValidator.validate(ageRecipients)
    }
}

public struct FileRecoveryConfigurationStore: Sendable {
    private static let maximumBytes = 16 * 1024
    private let root: URL
    private var configurationURL: URL { root.appending(path: "recovery.json") }

    public init(root: URL) {
        self.root = root
    }

    public func configuration() throws -> RecoveryConfiguration? {
        try SecureFileSystem.ensurePrivateDirectory(root)
        guard try SecureFileSystem.fileExists(configurationURL) else { return nil }
        let data = try SecureFileSystem.readRegularFile(configurationURL, maximumBytes: Self.maximumBytes)
        let decoded = try JSONDecoder().decode(RecoveryConfiguration.self, from: data)
        return try RecoveryConfiguration(ageRecipients: decoded.ageRecipients)
    }

    public func save(_ configuration: RecoveryConfiguration) throws {
        let validated = try RecoveryConfiguration(ageRecipients: configuration.ageRecipients)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try SecureFileSystem.writeAtomically(encoder.encode(validated), to: configurationURL)
    }
}

public struct SecretBackupRecord: Codable, Equatable, Sendable {
    public let metadata: SecretMetadata
    public let secret: Data

    public init(metadata: SecretMetadata, secret: Data) {
        self.metadata = metadata
        self.secret = secret
    }
}

public struct SecretBackupBundle: Codable, Equatable, Sendable {
    public static let currentSchemaVersion = 1
    public static let maximumEncodedBytes = 16 * 1024 * 1024

    public let schemaVersion: Int
    public let createdAt: Date
    public let records: [SecretBackupRecord]

    public init(
        schemaVersion: Int = currentSchemaVersion,
        createdAt: Date = Date(),
        records: [SecretBackupRecord]
    ) throws {
        self.schemaVersion = schemaVersion
        self.createdAt = createdAt
        self.records = records
        try validate()
    }

    public func encoded() throws -> Data {
        try validate()
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(self)
        guard data.count <= Self.maximumEncodedBytes else { throw KeyCourierError.invalidBackup }
        return data
    }

    public static func decode(_ data: Data) throws -> SecretBackupBundle {
        guard !data.isEmpty, data.count <= maximumEncodedBytes else {
            throw KeyCourierError.invalidBackup
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let bundle = try decoder.decode(SecretBackupBundle.self, from: data)
        try bundle.validate()
        return bundle
    }

    private func validate() throws {
        guard schemaVersion == Self.currentSchemaVersion,
              createdAt <= Date().addingTimeInterval(5 * 60),
              !records.isEmpty,
              records.count <= 500,
              Set(records.map(\.metadata.id)).count == records.count,
              records.allSatisfy({ record in
                  !record.secret.isEmpty
                      && record.secret.count <= 64 * 1024
                      && validMetadata(record.metadata)
              }) else {
            throw KeyCourierError.invalidBackup
        }
    }

    private func validMetadata(_ metadata: SecretMetadata) -> Bool {
        let labels = [
            metadata.displayName,
            metadata.ownerName,
            metadata.projectName,
            metadata.environmentName,
        ].compactMap { $0 }
        return !metadata.displayName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && labels.allSatisfy({ label in
                label.count <= 80
                    && label.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) })
            })
            && (metadata.expiresAt.map({ $0 > metadata.createdAt }) ?? true)
    }
}

public enum RecoveryBackupFile {
    private static let maximumBytes = 32 * 1024 * 1024

    public static func write(_ encryptedData: Data, to url: URL) throws {
        guard !encryptedData.isEmpty, encryptedData.count <= maximumBytes else {
            throw KeyCourierError.invalidBackup
        }
        try SecureFileSystem.writeAtomically(
            encryptedData,
            to: url,
            directoryPolicy: .existingOwnerControlled
        )
    }

    public static func read(from url: URL) throws -> Data {
        try SecureFileSystem.readRegularFile(url, maximumBytes: maximumBytes)
    }
}

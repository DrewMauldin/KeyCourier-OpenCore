import Foundation

public struct FileMetadataStore: Sendable {
    private static let maximumMetadataBytes = 256 * 1024

    private let root: URL
    private let trustedAnchor: URL?
    private var secretsURL: URL { root.appending(path: "secrets.json") }
    private var consumersURL: URL { root.appending(path: "consumers.json") }

    public init(root: URL, trustedAnchor: URL? = nil) {
        self.root = root
        self.trustedAnchor = trustedAnchor
    }

    public func secrets() throws -> [SecretMetadata] {
        try read([SecretMetadata].self, from: secretsURL)
            .map { try validated($0) }
            .sorted { $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending }
    }

    public func consumers() throws -> [ConsumerProfile] {
        try read([ConsumerProfile].self, from: consumersURL)
            .map {
                try ConsumerProfile(
                    id: $0.id,
                    displayName: $0.displayName,
                    targetID: $0.targetID,
                    destination: $0.destination
                )
            }
            .sorted { $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending }
    }

    public func save(_ metadata: SecretMetadata) throws {
        let metadata = try validated(metadata)
        var records = try secrets()
        if let index = records.firstIndex(where: { $0.id == metadata.id }) {
            records[index] = metadata
        } else {
            records.append(metadata)
        }
        try write(records, to: secretsURL)
    }

    public func save(_ profile: ConsumerProfile) throws {
        let profile = try ConsumerProfile(
            id: profile.id,
            displayName: profile.displayName,
            targetID: profile.targetID,
            destination: profile.destination
        )
        var records = try consumers()
        if let index = records.firstIndex(where: { $0.id == profile.id }) {
            records[index] = profile
        } else {
            records.append(profile)
        }
        try write(records, to: consumersURL)
    }

    public func registerMissingConsumers(_ profiles: [ConsumerProfile]) throws {
        var records = try consumers()
        var registeredIDs = Set(records.map(\.id))
        var changed = false

        for profile in profiles where !registeredIDs.contains(profile.id) {
            records.append(profile)
            registeredIDs.insert(profile.id)
            changed = true
        }

        if changed {
            try write(records, to: consumersURL)
        }
    }

    public func removeSecret(id: SecretID) throws {
        try write(try secrets().filter { $0.id != id }, to: secretsURL)
    }

    /// Move metadata from an older Store-only directory into the shared
    /// Automation/Store directory. Secret values remain in Keychain and are
    /// never read by this migration. Existing metadata always wins, and
    /// remote approval flags are disabled unless the caller explicitly opts in.
    @discardableResult
    public func migrateSecretsIfEmpty(
        from legacyStore: FileMetadataStore,
        allowingRemoteApproval: Bool = false
    ) throws -> Int {
        let current = try secrets()
        guard current.isEmpty else { return 0 }

        let legacy = try legacyStore.secrets()
        guard !legacy.isEmpty,
              legacy.count <= 200,
              Set(legacy.map(\.id)).count == legacy.count else {
            return 0
        }

        let migrated = legacy.map { metadata in
            SecretMetadata(
                secretID: metadata.secretID,
                displayName: metadata.displayName,
                kind: metadata.kind,
                materialKind: metadata.materialKind,
                createdAt: metadata.createdAt,
                updatedAt: metadata.updatedAt,
                ownerName: metadata.ownerName,
                projectName: metadata.projectName,
                environmentName: metadata.environmentName,
                rotationDueAt: metadata.rotationDueAt,
                expiresAt: metadata.expiresAt,
                allowsTelegramApproval: allowingRemoteApproval && metadata.allowsTelegramApproval,
                allowsCompanionApproval: allowingRemoteApproval && metadata.allowsCompanionApproval
            )
        }
        try write(migrated, to: secretsURL)
        return migrated.count
    }

    public func removeConsumer(id: ConsumerID) throws {
        try write(try consumers().filter { $0.id != id }, to: consumersURL)
    }

    private func validated(_ metadata: SecretMetadata) throws -> SecretMetadata {
        let name = metadata.displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        let owner = try validatedOptionalLabel(metadata.ownerName)
        let project = try validatedOptionalLabel(metadata.projectName)
        let environment = try validatedOptionalLabel(metadata.environmentName)
        guard !name.isEmpty,
              name.count <= 80,
              name.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }),
              metadata.expiresAt.map({ $0 > metadata.createdAt }) ?? true else {
            throw KeyCourierError.invalidMetadata
        }
        return SecretMetadata(
            secretID: metadata.secretID,
            displayName: name,
            kind: metadata.kind,
            materialKind: metadata.materialKind,
            createdAt: metadata.createdAt,
            updatedAt: metadata.updatedAt,
            ownerName: owner,
            projectName: project,
            environmentName: environment,
            rotationDueAt: metadata.rotationDueAt,
            expiresAt: metadata.expiresAt,
            allowsTelegramApproval: metadata.allowsTelegramApproval,
            allowsCompanionApproval: metadata.allowsCompanionApproval
        )
    }

    private func validatedOptionalLabel(_ value: String?) throws -> String? {
        guard let value else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        guard trimmed.count <= 80,
              trimmed.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            throw KeyCourierError.invalidMetadata
        }
        return trimmed
    }

    private func read<Element: Decodable>(_ type: [Element].Type, from url: URL) throws -> [Element] {
        try SecureFileSystem.ensurePrivateDirectory(root, trustedAnchor: trustedAnchor)
        guard try SecureFileSystem.fileExists(url, trustedAnchor: trustedAnchor) else {
            return []
        }
        let data = try SecureFileSystem.readRegularFile(
            url,
            maximumBytes: Self.maximumMetadataBytes,
            trustedAnchor: trustedAnchor
        )
        return try JSONDecoder().decode(type, from: data)
    }

    private func write<Value: Encodable>(_ value: Value, to url: URL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try SecureFileSystem.writeAtomically(
            encoder.encode(value),
            to: url,
            trustedAnchor: trustedAnchor
        )
    }
}

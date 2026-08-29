import Foundation

public struct TrustedCompanionDevice: Codable, Equatable, Identifiable, Sendable {
    public var id: UUID { registration.id }
    public let registration: CompanionDeviceRegistration
    public let approvedAt: Date

    public init(registration: CompanionDeviceRegistration, approvedAt: Date = Date()) throws {
        let registration = try registration.validated()
        guard registration.status == .pending || registration.status == .approved else {
            throw CompanionProtocolError.invalidRecord
        }
        self.registration = registration
        self.approvedAt = approvedAt
    }
}

public struct CompanionConfiguration: Codable, Equatable, Sendable {
    public var isEnabled: Bool
    public var trustedDevice: TrustedCompanionDevice?
    /// The opaque CloudKit user record name that approved the trusted device.
    /// A missing value is retained for legacy files but never treated as a
    /// valid binding for an existing trusted device.
    public var accountIdentifier: String?
    public var processedDecisionIDs: [UUID]
    public var processedEnvelopeIDs: [UUID]

    public init(
        isEnabled: Bool = false,
        trustedDevice: TrustedCompanionDevice? = nil,
        accountIdentifier: String? = nil,
        processedDecisionIDs: [UUID] = [],
        processedEnvelopeIDs: [UUID] = []
    ) {
        self.isEnabled = isEnabled
        self.trustedDevice = trustedDevice
        self.accountIdentifier = accountIdentifier
        self.processedDecisionIDs = processedDecisionIDs
        self.processedEnvelopeIDs = processedEnvelopeIDs
    }

    public func isBound(to activeAccountIdentifier: String) -> Bool {
        guard !activeAccountIdentifier.isEmpty else { return false }
        guard trustedDevice != nil else { return true }
        return accountIdentifier == activeAccountIdentifier
    }
}

public struct FileCompanionConfigurationStore: Sendable {
    private static let maximumBytes = 128 * 1024
    private static let maximumProcessedIDs = 400
    private let root: URL
    private let trustedAnchor: URL?
    private var fileURL: URL { root.appending(path: "companion.json") }

    public init(root: URL, trustedAnchor: URL? = nil) {
        self.root = root
        self.trustedAnchor = trustedAnchor
    }

    public func configuration() throws -> CompanionConfiguration {
        try SecureFileSystem.ensurePrivateDirectory(root, trustedAnchor: trustedAnchor)
        guard try SecureFileSystem.fileExists(fileURL, trustedAnchor: trustedAnchor) else {
            return CompanionConfiguration()
        }
        let data = try SecureFileSystem.readRegularFile(
            fileURL,
            maximumBytes: Self.maximumBytes,
            trustedAnchor: trustedAnchor
        )
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try validated(decoder.decode(CompanionConfiguration.self, from: data))
    }

    public func save(_ configuration: CompanionConfiguration) throws {
        let configuration = try validated(configuration)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try SecureFileSystem.writeAtomically(
            encoder.encode(configuration),
            to: fileURL,
            trustedAnchor: trustedAnchor
        )
    }

    public func setEnabled(_ isEnabled: Bool) throws -> CompanionConfiguration {
        var configuration = try configuration()
        configuration.isEnabled = isEnabled
        try save(configuration)
        return configuration
    }

    public func trust(
        _ registration: CompanionDeviceRegistration,
        accountIdentifier: String? = nil
    ) throws -> CompanionConfiguration {
        if let accountIdentifier {
            try Self.validateAccountIdentifier(accountIdentifier)
        }
        var configuration = try configuration()
        configuration.trustedDevice = try TrustedCompanionDevice(registration: registration)
        configuration.accountIdentifier = accountIdentifier
        configuration.isEnabled = true
        configuration.processedDecisionIDs.removeAll()
        configuration.processedEnvelopeIDs.removeAll()
        try save(configuration)
        return configuration
    }

    public func removeTrustedDevice() throws -> CompanionConfiguration {
        var configuration = try configuration()
        configuration.trustedDevice = nil
        configuration.accountIdentifier = nil
        configuration.processedDecisionIDs.removeAll()
        configuration.processedEnvelopeIDs.removeAll()
        try save(configuration)
        return configuration
    }

    /// Clear a trust that cannot be bound to the current iCloud account. The
    /// user must explicitly register and approve the companion again.
    public func requireRePair() throws -> CompanionConfiguration {
        try removeTrustedDevice()
    }

    public func markDecisionProcessed(_ id: UUID) throws -> CompanionConfiguration {
        var configuration = try configuration()
        Self.append(id, to: &configuration.processedDecisionIDs)
        try save(configuration)
        return configuration
    }

    public func markEnvelopeProcessed(_ id: UUID) throws -> CompanionConfiguration {
        var configuration = try configuration()
        Self.append(id, to: &configuration.processedEnvelopeIDs)
        try save(configuration)
        return configuration
    }

    private func validated(_ configuration: CompanionConfiguration) throws -> CompanionConfiguration {
        guard configuration.processedDecisionIDs.count <= Self.maximumProcessedIDs,
              configuration.processedEnvelopeIDs.count <= Self.maximumProcessedIDs,
              Set(configuration.processedDecisionIDs).count == configuration.processedDecisionIDs.count,
              Set(configuration.processedEnvelopeIDs).count == configuration.processedEnvelopeIDs.count else {
            throw CompanionProtocolError.invalidRecord
        }
        if let accountIdentifier = configuration.accountIdentifier {
            try Self.validateAccountIdentifier(accountIdentifier)
        }
        if let trustedDevice = configuration.trustedDevice {
            _ = try TrustedCompanionDevice(
                registration: trustedDevice.registration,
                approvedAt: trustedDevice.approvedAt
            )
        }
        return configuration
    }

    private static func validateAccountIdentifier(_ accountIdentifier: String) throws {
        guard !accountIdentifier.isEmpty,
              accountIdentifier.count <= 256,
              accountIdentifier.unicodeScalars.allSatisfy({
                  !CharacterSet.controlCharacters.contains($0)
              }) else {
            throw CompanionProtocolError.invalidRecord
        }
    }

    private static func append(_ id: UUID, to ids: inout [UUID]) {
        guard !ids.contains(id) else { return }
        ids.append(id)
        if ids.count > maximumProcessedIDs {
            ids.removeFirst(ids.count - maximumProcessedIDs)
        }
    }
}

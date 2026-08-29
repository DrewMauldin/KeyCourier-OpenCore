import CryptoKit
import Foundation

public struct BridgeQueue: Sendable {
    public static let maximumPendingRecords = 100
    public static let maximumTotalRecords = 400

    public let root: URL

    private let maximumPending: Int
    private let maximumTotal: Int
    private let trustedAnchor: URL?

    private var pairingRoot: URL { root.appending(path: "Pairing", directoryHint: .isDirectory) }
    private var registrationsRoot: URL { pairingRoot.appending(path: "Registrations", directoryHint: .isDirectory) }
    private var proposalsRoot: URL { pairingRoot.appending(path: "Proposals", directoryHint: .isDirectory) }
    private var grantsRoot: URL { pairingRoot.appending(path: "Grants", directoryHint: .isDirectory) }
    private var revocationsRoot: URL { pairingRoot.appending(path: "Revocations", directoryHint: .isDirectory) }
    private var requestsRoot: URL { root.appending(path: "Requests", directoryHint: .isDirectory) }
    private var commandsRoot: URL { root.appending(path: "Commands", directoryHint: .isDirectory) }
    private var receiptsRoot: URL { root.appending(path: "Receipts", directoryHint: .isDirectory) }
    private var claimsRoot: URL { root.appending(path: "Claims", directoryHint: .isDirectory) }

    public init(
        root: URL,
        maximumPendingRecords: Int = Self.maximumPendingRecords,
        maximumTotalRecords: Int = Self.maximumTotalRecords,
        trustedAnchor: URL? = nil
    ) {
        self.root = root
        self.maximumPending = max(1, maximumPendingRecords)
        self.maximumTotal = max(1, maximumTotalRecords)
        self.trustedAnchor = trustedAnchor
    }

    public func prepare() throws {
        for directory in [
            root, pairingRoot, registrationsRoot, proposalsRoot, grantsRoot, revocationsRoot,
            requestsRoot, commandsRoot, receiptsRoot, claimsRoot
        ] {
            try SecureFileSystem.ensurePrivateDirectory(directory, trustedAnchor: trustedAnchor)
        }
    }

    @discardableResult
    public func enqueue(_ request: SignedBridgeRequest) throws -> URL {
        try request.validate()
        try prepare()
        try pruneExpiredClaims(at: Date())
        let destination = requestsRoot.appending(path: requestFileName(request.id))
        let digest = try request.digest()
        if try SecureFileSystem.fileExists(destination, trustedAnchor: trustedAnchor) {
            let existing = try read(SignedBridgeRequest.self, from: destination, maximumBytes: 16 * 1024)
            try existing.validate()
            guard try existing.digest() == digest else {
                throw BridgeProtocolError.conflictingRecord
            }
            if try hasLiveClaim(kind: .request, id: request.id, at: Date()) {
                throw BridgeProtocolError.replayedRecord
            }
            return destination
        }
        if try hasLiveClaim(kind: .request, id: request.id, at: Date()) {
            throw BridgeProtocolError.replayedRecord
        }
        try enforceCapacity(in: requestsRoot)
        try writeExclusively(request, to: destination)
        return destination
    }

    public func pendingRequests(at date: Date = Date()) throws -> [SignedBridgeRequest] {
        try prepare()
        return try files(in: requestsRoot, suffix: ".request.json").compactMap { file in
            guard let request = try? read(SignedBridgeRequest.self, from: file, maximumBytes: 16 * 1024),
                  file.lastPathComponent == requestFileName(request.id),
                  (try? request.validate(at: date)) != nil,
                  ((try? hasLiveClaim(kind: .request, id: request.id, at: date)) ?? true) == false else {
                return nil
            }
            return request
        }
        .sorted { $0.request.createdAt > $1.request.createdAt }
        .prefix(maximumPending)
        .map { $0 }
    }

    public func request(for requestID: UUID, at date: Date = Date()) throws -> SignedBridgeRequest? {
        try prepare()
        let destination = requestsRoot.appending(path: requestFileName(requestID))
        guard try SecureFileSystem.fileExists(destination, trustedAnchor: trustedAnchor) else { return nil }
        let request = try read(SignedBridgeRequest.self, from: destination, maximumBytes: 16 * 1024)
        try request.validate(at: date)
        guard request.id == requestID else { throw BridgeProtocolError.invalidRecord }
        guard try !hasLiveClaim(kind: .request, id: requestID, at: date) else { return nil }
        return request
    }

    public func removeRequest(_ requestID: UUID) throws {
        try remove(requestsRoot.appending(path: requestFileName(requestID)))
    }

    @discardableResult
    public func enqueue(_ command: BridgeDeliveryCommand) throws -> URL {
        try command.validate()
        try prepare()
        try pruneExpiredClaims(at: Date())
        if try receipt(for: command.commandID) != nil {
            throw BridgeProtocolError.replayedRecord
        }
        let destination = commandsRoot.appending(path: commandFileName(command.commandID))
        let digest = try command.digest()
        if try SecureFileSystem.fileExists(destination, trustedAnchor: trustedAnchor) {
            let existing = try read(BridgeDeliveryCommand.self, from: destination, maximumBytes: 256 * 1024)
            try existing.validate()
            guard try existing.digest() == digest else {
                throw BridgeProtocolError.conflictingRecord
            }
            if try hasLiveClaim(kind: .command, id: command.commandID, at: Date()) {
                throw BridgeProtocolError.replayedRecord
            }
            if try receipt(for: command.commandID) != nil {
                throw BridgeProtocolError.replayedRecord
            }
            return destination
        }
        if try hasLiveClaim(kind: .command, id: command.commandID, at: Date()),
           try receipt(for: command.commandID) == nil {
            throw BridgeProtocolError.replayedRecord
        }
        try enforceCapacity(in: commandsRoot)
        try writeExclusively(command, to: destination)
        return destination
    }

    public func pendingCommands(at date: Date = Date()) throws -> [BridgeDeliveryCommand] {
        try prepare()
        return try files(in: commandsRoot, suffix: ".command.json").compactMap { file in
            guard let command = try? read(BridgeDeliveryCommand.self, from: file, maximumBytes: 256 * 1024),
                  file.lastPathComponent == commandFileName(command.commandID),
                  (try? command.validate(at: date)) != nil,
                  ((try? receipt(for: command.commandID)) ?? nil) == nil,
                  ((try? hasLiveClaim(kind: .command, id: command.commandID, at: date)) ?? true) == false else {
                return nil
            }
            return command
        }
        .sorted { $0.createdAt > $1.createdAt }
        .prefix(maximumPending)
        .map { $0 }
    }

    public func command(
        forRequestID requestID: UUID,
        at date: Date = Date()
    ) throws -> BridgeDeliveryCommand? {
        try prepare()
        let matches: [BridgeDeliveryCommand] = try files(
            in: commandsRoot,
            suffix: ".command.json"
        ).compactMap { file -> BridgeDeliveryCommand? in
            guard let command = try? read(BridgeDeliveryCommand.self, from: file, maximumBytes: 256 * 1024),
                  file.lastPathComponent == commandFileName(command.commandID),
                  (try? command.validate(at: date)) != nil,
                  command.requestID == requestID else {
                return nil
            }
            return command
        }
        guard matches.count <= 1 else { throw BridgeProtocolError.conflictingRecord }
        return matches.first
    }

    public func removeCommand(_ commandID: UUID) throws {
        try remove(commandsRoot.appending(path: commandFileName(commandID)))
    }

    public func command(for commandID: UUID, at date: Date = Date()) throws -> BridgeDeliveryCommand? {
        try prepare()
        let destination = commandsRoot.appending(path: commandFileName(commandID))
        guard try SecureFileSystem.fileExists(destination, trustedAnchor: trustedAnchor) else { return nil }
        let command = try read(BridgeDeliveryCommand.self, from: destination, maximumBytes: 256 * 1024)
        try command.validate(at: date)
        guard command.commandID == commandID else { throw BridgeProtocolError.invalidRecord }
        return command
    }

    @discardableResult
    public func record(_ receipt: SignedBridgeReceipt) throws -> URL {
        try receipt.validate()
        try prepare()
        try pruneExpiredClaims(at: Date())
        let destination = receiptsRoot.appending(path: receiptFileName(receipt.commandID))
        let digest = try receipt.digest()
        if try SecureFileSystem.fileExists(destination, trustedAnchor: trustedAnchor) {
            let existing = try read(SignedBridgeReceipt.self, from: destination, maximumBytes: 8 * 1024)
            try existing.validate()
            guard try existing.digest() == digest else {
                throw BridgeProtocolError.conflictingRecord
            }
            return destination
        }
        try enforceCapacity(in: receiptsRoot)
        try writeExclusively(receipt, to: destination)
        return destination
    }

    public func receipt(for commandID: UUID) throws -> SignedBridgeReceipt? {
        try prepare()
        let destination = receiptsRoot.appending(path: receiptFileName(commandID))
        guard try SecureFileSystem.fileExists(destination, trustedAnchor: trustedAnchor) else { return nil }
        let receipt = try read(SignedBridgeReceipt.self, from: destination, maximumBytes: 8 * 1024)
        try receipt.validate()
        guard receipt.commandID == commandID else { throw BridgeProtocolError.invalidRecord }
        return receipt
    }

    public func removeReceipt(_ commandID: UUID) throws {
        try remove(receiptsRoot.appending(path: receiptFileName(commandID)))
    }

    public func receipts() throws -> [SignedBridgeReceipt] {
        try prepare()
        return try files(in: receiptsRoot, suffix: ".receipt.json").compactMap { file in
            guard let receipt = try? read(SignedBridgeReceipt.self, from: file, maximumBytes: 8 * 1024),
                  file.lastPathComponent == receiptFileName(receipt.commandID),
                  (try? receipt.validate()) != nil else { return nil }
            return receipt
        }
        .sorted { $0.receipt.recordedAt > $1.receipt.recordedAt }
    }

    public func receipt(forRequestID requestID: UUID) throws -> SignedBridgeReceipt? {
        try receipts().first { $0.receipt.requestID == requestID }
    }

    public func claimRequest(
        _ request: SignedBridgeRequest,
        at date: Date = Date()
    ) throws -> BridgeClaimResult {
        try request.validate(at: date)
        try prepare()
        let canonicalURL = requestsRoot.appending(path: requestFileName(request.id))
        guard try SecureFileSystem.fileExists(canonicalURL, trustedAnchor: trustedAnchor) else {
            throw BridgeProtocolError.invalidRecord
        }
        let canonical = try read(SignedBridgeRequest.self, from: canonicalURL, maximumBytes: 16 * 1024)
        try canonical.validate(at: date)
        guard canonical.id == request.id, try canonical.digest() == request.digest() else {
            throw BridgeProtocolError.conflictingRecord
        }
        return try claim(
            kind: .request,
            id: request.id,
            digest: request.digest(),
            expiresAt: request.request.expiresAt,
            at: date
        )
    }

    public func claimCommand(
        _ command: BridgeDeliveryCommand,
        at date: Date = Date()
    ) throws -> BridgeClaimResult {
        try command.validate(at: date)
        try prepare()
        if try receipt(for: command.commandID) != nil {
            throw BridgeProtocolError.replayedRecord
        }
        let canonicalURL = commandsRoot.appending(path: commandFileName(command.commandID))
        guard try SecureFileSystem.fileExists(canonicalURL, trustedAnchor: trustedAnchor) else {
            throw BridgeProtocolError.invalidRecord
        }
        let canonical = try read(BridgeDeliveryCommand.self, from: canonicalURL, maximumBytes: 256 * 1024)
        try canonical.validate(at: date)
        guard canonical.commandID == command.commandID,
              try canonical.digest() == command.digest() else {
            throw BridgeProtocolError.conflictingRecord
        }
        return try claim(
            kind: .command,
            id: command.commandID,
            digest: command.digest(),
            expiresAt: command.expiresAt,
            at: date
        )
    }

    public func pruneExpiredClaims(at date: Date = Date()) throws {
        try prepare()
        for file in try files(in: claimsRoot, suffix: ".claim.json") {
            guard let claim = try? read(ClaimRecord.self, from: file, maximumBytes: 4 * 1024),
                  claim.expiresAt.timeIntervalSince1970.isFinite else {
                continue
            }
            if claim.expiresAt <= date {
                try remove(file)
            }
        }
    }

    public func pruneExpiredRecords(at date: Date = Date()) throws {
        try prepare()
        try pruneExpiredClaims(at: date)
        try pruneExpiredFiles(in: requestsRoot, suffix: ".request.json", at: date) { file in
            try read(SignedBridgeRequest.self, from: file, maximumBytes: 16 * 1024).request.expiresAt
        }
        try pruneExpiredFiles(in: commandsRoot, suffix: ".command.json", at: date) { file in
            try read(BridgeDeliveryCommand.self, from: file, maximumBytes: 256 * 1024).expiresAt
        }
        try pruneExpiredFiles(in: registrationsRoot, suffix: ".registration.json", at: date) { file in
            try read(BridgeRegistration.self, from: file, maximumBytes: 16 * 1024).expiresAt
        }
        try pruneExpiredFiles(in: proposalsRoot, suffix: ".proposal.json", at: date) { file in
            try read(BridgePairingProposal.self, from: file, maximumBytes: 16 * 1024).expiresAt
        }
        try pruneExpiredFiles(in: receiptsRoot, suffix: ".receipt.json", at: date) { file in
            try read(SignedBridgeReceipt.self, from: file, maximumBytes: 8 * 1024)
                .receipt.recordedAt.addingTimeInterval(24 * 60 * 60)
        }
    }

    public func purgeAll() throws {
        try prepare()
        for directory in recordDirectories {
            for file in try files(in: directory, suffix: ".json") {
                try SecureFileSystem.removeEntryWithoutFollowing(file, trustedAnchor: trustedAnchor)
            }
        }
    }

    @discardableResult
    public func save(_ registration: BridgeRegistration) throws -> URL {
        try registration.validate()
        try prepare()
        let destination = registrationsRoot.appending(path: registrationFileName(registration.bridgeID))
        if try SecureFileSystem.fileExists(destination, trustedAnchor: trustedAnchor) {
            let existing = try read(BridgeRegistration.self, from: destination, maximumBytes: 16 * 1024)
            try existing.validate()
            guard try existing.digest() == registration.digest() else {
                throw BridgeProtocolError.conflictingRecord
            }
            return destination
        }
        try enforceCapacity(in: registrationsRoot)
        try writeExclusively(registration, to: destination)
        return destination
    }

    public func registrations() throws -> [BridgeRegistration] {
        try prepare()
        return try files(in: registrationsRoot, suffix: ".registration.json").compactMap { file in
            guard let record = try? read(BridgeRegistration.self, from: file, maximumBytes: 16 * 1024),
                  file.lastPathComponent == registrationFileName(record.bridgeID),
                  (try? record.validate()) != nil else { return nil }
            return record
        }
        .sorted { $0.createdAt > $1.createdAt }
    }

    public func registration(for bridgeID: UUID) throws -> BridgeRegistration? {
        try prepare()
        let destination = registrationsRoot.appending(path: registrationFileName(bridgeID))
        guard try SecureFileSystem.fileExists(destination, trustedAnchor: trustedAnchor) else { return nil }
        let registration = try read(BridgeRegistration.self, from: destination, maximumBytes: 16 * 1024)
        try registration.validate()
        guard registration.bridgeID == bridgeID else { throw BridgeProtocolError.invalidRecord }
        return registration
    }

    public func removeRegistration(for bridgeID: UUID) throws {
        try remove(registrationsRoot.appending(path: registrationFileName(bridgeID)))
    }

    @discardableResult
    public func save(_ proposal: BridgePairingProposal) throws -> URL {
        try proposal.validate()
        try prepare()
        let destination = proposalsRoot.appending(path: proposalFileName(proposal.bridgeID))
        if try SecureFileSystem.fileExists(destination, trustedAnchor: trustedAnchor) {
            let existing = try read(BridgePairingProposal.self, from: destination, maximumBytes: 16 * 1024)
            try existing.validate()
            guard try existing.digest() == proposal.digest() else {
                throw BridgeProtocolError.conflictingRecord
            }
            return destination
        }
        try enforceCapacity(in: proposalsRoot)
        try writeExclusively(proposal, to: destination)
        return destination
    }

    public func proposal(for bridgeID: UUID) throws -> BridgePairingProposal? {
        try prepare()
        let destination = proposalsRoot.appending(path: proposalFileName(bridgeID))
        guard try SecureFileSystem.fileExists(destination, trustedAnchor: trustedAnchor) else { return nil }
        let proposal = try read(BridgePairingProposal.self, from: destination, maximumBytes: 16 * 1024)
        try proposal.validate()
        guard proposal.bridgeID == bridgeID else { throw BridgeProtocolError.invalidRecord }
        return proposal
    }

    public func removeProposal(for bridgeID: UUID) throws {
        try remove(proposalsRoot.appending(path: proposalFileName(bridgeID)))
    }

    @discardableResult
    public func save(_ grant: BridgeTrustGrant) throws -> URL {
        try grant.validate()
        try prepare()
        let destination = grantsRoot.appending(path: grantFileName(grant.bridgeID))
        if try SecureFileSystem.fileExists(destination, trustedAnchor: trustedAnchor) {
            let existing = try read(BridgeTrustGrant.self, from: destination, maximumBytes: 16 * 1024)
            try existing.validate()
            guard try existing.digest() == grant.digest() else {
                throw BridgeProtocolError.conflictingRecord
            }
            return destination
        }
        try enforceCapacity(in: grantsRoot)
        try writeExclusively(grant, to: destination)
        return destination
    }

    public func grant(for bridgeID: UUID) throws -> BridgeTrustGrant? {
        try prepare()
        let destination = grantsRoot.appending(path: grantFileName(bridgeID))
        guard try SecureFileSystem.fileExists(destination, trustedAnchor: trustedAnchor) else { return nil }
        let grant = try read(BridgeTrustGrant.self, from: destination, maximumBytes: 16 * 1024)
        try grant.validate()
        guard grant.bridgeID == bridgeID else { throw BridgeProtocolError.invalidRecord }
        return grant
    }

    @discardableResult
    public func save(_ revocation: BridgeTrustRevocation) throws -> URL {
        try revocation.validate()
        try prepare()
        let destination = revocationsRoot.appending(path: revocationFileName(revocation.bridgeID))
        if try SecureFileSystem.fileExists(destination, trustedAnchor: trustedAnchor) {
            let existing = try read(
                BridgeTrustRevocation.self,
                from: destination,
                maximumBytes: 8 * 1024
            )
            try existing.validate()
            guard try existing.digest() == revocation.digest() else {
                throw BridgeProtocolError.conflictingRecord
            }
            return destination
        }
        try enforceCapacity(in: revocationsRoot)
        try writeExclusively(revocation, to: destination)
        return destination
    }

    public func revocation(for bridgeID: UUID) throws -> BridgeTrustRevocation? {
        try prepare()
        let destination = revocationsRoot.appending(path: revocationFileName(bridgeID))
        guard try SecureFileSystem.fileExists(destination, trustedAnchor: trustedAnchor) else { return nil }
        let revocation = try read(
            BridgeTrustRevocation.self,
            from: destination,
            maximumBytes: 8 * 1024
        )
        try revocation.validate()
        guard revocation.bridgeID == bridgeID else { throw BridgeProtocolError.invalidRecord }
        return revocation
    }

    public func removeRevocation(for bridgeID: UUID) throws {
        try remove(revocationsRoot.appending(path: revocationFileName(bridgeID)))
    }

    private enum ClaimKind: String, Codable {
        case request
        case command
    }

    private struct ClaimRecord: Codable {
        let kind: ClaimKind
        let id: UUID
        let digest: Data
        let expiresAt: Date
    }

    private func claim(
        kind: ClaimKind,
        id: UUID,
        digest: Data,
        expiresAt: Date,
        at date: Date
    ) throws -> BridgeClaimResult {
        try prepare()
        try pruneExpiredClaims(at: date)
        let destination = claimsRoot.appending(path: claimFileName(kind: kind, id: id))
        if try SecureFileSystem.fileExists(destination, trustedAnchor: trustedAnchor) {
            let existing = try read(ClaimRecord.self, from: destination, maximumBytes: 4 * 1024)
            guard existing.kind == kind,
                  existing.id == id,
                  existing.digest.count == SHA256.byteCount,
                  existing.expiresAt.timeIntervalSince1970.isFinite else {
                throw BridgeProtocolError.invalidRecord
            }
            if existing.expiresAt > date {
                guard existing.digest == digest else {
                    throw BridgeProtocolError.conflictingRecord
                }
                return .alreadyClaimed
            }
            try remove(destination)
        }
        try enforceCapacity(in: claimsRoot)
        let record = ClaimRecord(kind: kind, id: id, digest: digest, expiresAt: expiresAt)
        do {
            try writeExclusively(record, to: destination)
        } catch KeyCourierError.replayedRequest {
            let existing = try read(ClaimRecord.self, from: destination, maximumBytes: 4 * 1024)
            guard existing.kind == kind, existing.id == id else {
                throw BridgeProtocolError.invalidRecord
            }
            guard existing.digest == digest else {
                throw BridgeProtocolError.conflictingRecord
            }
            return .alreadyClaimed
        } catch BridgeProtocolError.replayedRecord {
            let existing = try read(ClaimRecord.self, from: destination, maximumBytes: 4 * 1024)
            guard existing.kind == kind, existing.id == id else {
                throw BridgeProtocolError.invalidRecord
            }
            guard existing.digest == digest else {
                throw BridgeProtocolError.conflictingRecord
            }
            return .alreadyClaimed
        }
        return .claimed
    }

    private func hasLiveClaim(kind: ClaimKind, id: UUID, at date: Date) throws -> Bool {
        let destination = claimsRoot.appending(path: claimFileName(kind: kind, id: id))
        guard try SecureFileSystem.fileExists(destination, trustedAnchor: trustedAnchor) else { return false }
        let claim = try read(ClaimRecord.self, from: destination, maximumBytes: 4 * 1024)
        guard claim.kind == kind,
              claim.id == id,
              claim.digest.count == SHA256.byteCount,
              claim.expiresAt.timeIntervalSince1970.isFinite else {
            throw BridgeProtocolError.invalidRecord
        }
        if claim.expiresAt <= date {
            try remove(destination)
            return false
        }
        return true
    }

    private func enforceCapacity(in activeDirectory: URL) throws {
        try pruneExpiredRecords()
        let pendingCount = try files(in: activeDirectory, suffix: ".json").count
        guard pendingCount < maximumPending else { throw BridgeProtocolError.queueLimitExceeded }
        let totalCount = try recordDirectories.reduce(0) { partial, directory in
            partial + (try files(in: directory, suffix: ".json").count)
        }
        guard totalCount < maximumTotal else { throw BridgeProtocolError.queueLimitExceeded }
    }

    private var recordDirectories: [URL] {
        [registrationsRoot, proposalsRoot, grantsRoot, revocationsRoot, requestsRoot, commandsRoot, receiptsRoot, claimsRoot]
    }

    private func pruneExpiredFiles(
        in directory: URL,
        suffix: String,
        at date: Date,
        expiresAt: (URL) throws -> Date
    ) throws {
        for file in try files(in: directory, suffix: suffix) {
            guard let expiry = try? expiresAt(file), expiry <= date else { continue }
            try remove(file)
        }
    }

    private func writeExclusively<T: Encodable>(_ value: T, to destination: URL) throws {
        let data = try encode(value)
        do {
            try SecureFileSystem.writeAtomicallyIfAbsent(
                data,
                to: destination,
                trustedAnchor: trustedAnchor
            )
        } catch KeyCourierError.replayedRequest {
            throw BridgeProtocolError.replayedRecord
        }
    }

    private func read<T: Decodable>(_ type: T.Type, from url: URL, maximumBytes: Int) throws -> T {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return try decoder.decode(
            type,
            from: SecureFileSystem.readRegularFile(
                url,
                maximumBytes: maximumBytes,
                trustedAnchor: trustedAnchor
            )
        )
    }

    private func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(value)
    }

    private func files(in directory: URL, suffix: String) throws -> [URL] {
        try SecureFileSystem.ensurePrivateDirectory(directory, trustedAnchor: trustedAnchor)
        return try FileManager.default.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        )
        .filter { $0.lastPathComponent.hasSuffix(suffix) }
        .sorted { $0.lastPathComponent < $1.lastPathComponent }
    }

    private func remove(_ url: URL) throws {
        try SecureFileSystem.removeRegularFile(url, trustedAnchor: trustedAnchor)
    }

    private func requestFileName(_ id: UUID) -> String { "\(id.uuidString.lowercased()).request.json" }
    private func commandFileName(_ id: UUID) -> String { "\(id.uuidString.lowercased()).command.json" }
    private func receiptFileName(_ id: UUID) -> String { "\(id.uuidString.lowercased()).receipt.json" }
    private func registrationFileName(_ id: UUID) -> String { "\(id.uuidString.lowercased()).registration.json" }
    private func proposalFileName(_ id: UUID) -> String { "\(id.uuidString.lowercased()).proposal.json" }
    private func grantFileName(_ id: UUID) -> String { "\(id.uuidString.lowercased()).grant.json" }
    private func revocationFileName(_ id: UUID) -> String { "\(id.uuidString.lowercased()).revocation.json" }
    private func claimFileName(kind: ClaimKind, id: UUID) -> String { "\(kind.rawValue)-\(id.uuidString.lowercased()).claim.json" }
}

import Darwin
import Foundation

public enum AgeRecipientValidator {
    public static func validate(_ recipients: [String], maximumCount: Int = 4) throws -> [String] {
        let allowedCharacters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789")
        guard !recipients.isEmpty,
              recipients.count <= maximumCount,
              Set(recipients).count == recipients.count,
              recipients.allSatisfy({ recipient in
                  recipient.hasPrefix("age1")
                      && recipient.count >= 20
                      && recipient.count <= 128
                      && recipient.unicodeScalars.allSatisfy(allowedCharacters.contains)
              }) else {
            throw KeyCourierError.malformedDestination
        }
        return recipients
    }
}

/// An owner-created remote destination. Requests contain only the profile ID;
/// these fields never come from an agent request.
public struct RemoteAgeProfile: Codable, Equatable, Identifiable, Sendable {
    public enum Consumer: Codable, Equatable, Sendable {
        case dotenv(path: String, variable: String)
    }

    public let id: ConsumerID
    public let displayName: String
    public let targetID: TargetID
    public let sshAlias: String
    public let helperPath: String
    public let ageRecipients: [String]
    public let consumer: Consumer

    public init(
        id: ConsumerID,
        displayName: String,
        targetID: TargetID,
        sshAlias: String,
        helperPath: String,
        ageRecipients: [String],
        consumer: Consumer
    ) throws {
        let name = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, name.count <= 80 else {
            throw KeyCourierError.malformedDestination
        }
        guard (try? TargetID(validating: sshAlias)) != nil else {
            throw KeyCourierError.malformedDestination
        }
        let helperPathAllowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/-")
        guard helperPath.hasPrefix("/"),
              !helperPath.contains("\0"),
              !helperPath.split(separator: "/").contains(".."),
              helperPath.count <= 1024,
              helperPath.unicodeScalars.allSatisfy(helperPathAllowed.contains) else {
            throw KeyCourierError.malformedDestination
        }
        _ = try AgeRecipientValidator.validate(ageRecipients)
        switch consumer {
        case .dotenv(let path, let variable):
            guard path.hasPrefix("/"),
                  !path.contains("\0"),
                  !path.split(separator: "/").contains(".."),
                  path.count <= 1024,
                  variable.count <= 128,
                  variable.first.map({ $0 == "_" || $0.isLetter }) == true,
                  variable.allSatisfy({ $0 == "_" || $0.isUppercase || $0.isNumber }) else {
                throw KeyCourierError.malformedDestination
            }
        }
        self.id = id
        self.displayName = name
        self.targetID = targetID
        self.sshAlias = sshAlias
        self.helperPath = helperPath
        self.ageRecipients = ageRecipients
        self.consumer = consumer
    }

    fileprivate func localConsumerProfile() throws -> ConsumerProfile {
        let destination: ConsumerDestination
        switch consumer {
        case .dotenv(let path, let variable):
            destination = .dotenv(path: path, variable: variable)
        }
        return try ConsumerProfile(
            id: id,
            displayName: displayName,
            targetID: targetID,
            destination: destination
        )
    }
}

public struct RemoteAgeAllowlist: Sendable {
    private let profiles: [ConsumerID: RemoteAgeProfile]

    public init(profiles: [RemoteAgeProfile]) throws {
        var result: [ConsumerID: RemoteAgeProfile] = [:]
        for profile in profiles {
            guard result[profile.id] == nil else {
                throw KeyCourierError.malformedDestination
            }
            result[profile.id] = profile
        }
        self.profiles = result
    }

    public func profile(for id: ConsumerID) -> RemoteAgeProfile? {
        profiles[id]
    }
}

public struct RemoteAgePayload: Codable, Equatable, Sendable {
    public static let currentSchemaVersion = 1

    public let schemaVersion: Int
    public let requestID: UUID
    public let secretID: SecretID
    public let targetID: TargetID
    public let consumerID: ConsumerID
    public let createdAt: Date
    public let expiresAt: Date
    public let secret: Data

    public init(request: SecretRequest, secret: Data) throws {
        guard !secret.isEmpty, secret.count <= 64 * 1024 else {
            throw KeyCourierError.malformedSecretValue
        }
        self.schemaVersion = Self.currentSchemaVersion
        self.requestID = request.id
        self.secretID = request.secretID
        self.targetID = request.targetID
        self.consumerID = request.consumerID
        self.createdAt = request.createdAt
        self.expiresAt = request.expiresAt
        self.secret = secret
    }

    public func validate(at date: Date = Date()) throws {
        guard schemaVersion == Self.currentSchemaVersion else {
            throw KeyCourierError.remotePackageInvalid
        }
        let duration = expiresAt.timeIntervalSince(createdAt)
        guard duration > 0, duration <= 24 * 60 * 60,
              createdAt <= date.addingTimeInterval(5 * 60),
              date <= expiresAt,
              !secret.isEmpty,
              secret.count <= 64 * 1024 else {
            throw KeyCourierError.remotePackageInvalid
        }
    }
}

public struct RemoteAgePackage: Codable, Equatable, Sendable {
    public static let currentSchemaVersion = 1
    private static let maximumCiphertextBytes = 128 * 1024

    public let schemaVersion: Int
    public let requestID: UUID
    public let targetID: TargetID
    public let consumerID: ConsumerID
    public let createdAt: Date
    public let expiresAt: Date
    public let ciphertext: Data

    public init(request: SecretRequest, ciphertext: Data) throws {
        guard !ciphertext.isEmpty, ciphertext.count <= Self.maximumCiphertextBytes else {
            throw KeyCourierError.remotePackageInvalid
        }
        self.schemaVersion = Self.currentSchemaVersion
        self.requestID = request.id
        self.targetID = request.targetID
        self.consumerID = request.consumerID
        self.createdAt = request.createdAt
        self.expiresAt = request.expiresAt
        self.ciphertext = ciphertext
    }

    public func validate(at date: Date = Date()) throws {
        guard schemaVersion == Self.currentSchemaVersion else {
            throw KeyCourierError.remotePackageInvalid
        }
        let duration = expiresAt.timeIntervalSince(createdAt)
        guard duration > 0, duration <= 24 * 60 * 60,
              createdAt <= date.addingTimeInterval(5 * 60),
              date <= expiresAt,
              !ciphertext.isEmpty,
              ciphertext.count <= Self.maximumCiphertextBytes else {
            throw KeyCourierError.remotePackageInvalid
        }
    }

    public func encoded() throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(self)
    }
}

public protocol AgeEncryptor: Sendable {
    func encrypt(_ plaintext: Data, recipients: [String]) throws -> Data
}

public protocol AgeDecryptor: Sendable {
    func decrypt(_ ciphertext: Data, profileID: ConsumerID) throws -> Data
}

public struct SystemAgeEncryptor: AgeEncryptor, Sendable {
    private let executableURL: URL?

    public init() {
        executableURL = Self.findExecutable()
    }

    public func encrypt(_ plaintext: Data, recipients: [String]) throws -> Data {
        guard let executableURL, !recipients.isEmpty else { throw KeyCourierError.ageUnavailable }
        let process = Process()
        process.executableURL = executableURL
        process.arguments = ["--armor"] + recipients.flatMap { ["--recipient", $0] }
        let input = Pipe()
        let output = Pipe()
        process.standardInput = input
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            input.fileHandleForWriting.write(plaintext)
            input.fileHandleForWriting.closeFile()
            let result = output.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            guard process.terminationStatus == 0, !result.isEmpty else {
                throw KeyCourierError.ageOperationFailed
            }
            return result
        } catch let error as KeyCourierError {
            throw error
        } catch {
            throw KeyCourierError.ageOperationFailed
        }
    }

    private static func findExecutable() -> URL? {
        [
            FileManager.default.homeDirectoryForCurrentUser.appending(path: ".local/bin/age").path,
            "/opt/homebrew/bin/age",
            "/usr/local/bin/age",
            "/usr/bin/age",
        ]
            .map { URL(filePath: $0) }
            .first { FileManager.default.isExecutableFile(atPath: $0.path) }
    }
}

public struct SystemAgeDecryptor: AgeDecryptor, Sendable {
    private let executableURL: URL?
    private let identityPath: String

    /// The identity path is host-local configuration and is never sent in a package.
    public init(identityPath: String) {
        self.executableURL = SystemAgeEncryptor.findExecutableForDecryptor()
        self.identityPath = identityPath
    }

    public func decrypt(_ ciphertext: Data, profileID: ConsumerID) throws -> Data {
        try decrypt(ciphertext)
    }

    public func decrypt(_ ciphertext: Data) throws -> Data {
        guard let executableURL else { throw KeyCourierError.ageUnavailable }
        let process = Process()
        process.executableURL = executableURL
        process.arguments = ["--decrypt", "--identity", identityPath]
        let input = Pipe()
        let output = Pipe()
        process.standardInput = input
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            input.fileHandleForWriting.write(ciphertext)
            input.fileHandleForWriting.closeFile()
            let result = output.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            guard process.terminationStatus == 0, !result.isEmpty else {
                throw KeyCourierError.ageOperationFailed
            }
            return result
        } catch let error as KeyCourierError {
            throw error
        } catch {
            throw KeyCourierError.ageOperationFailed
        }
    }
}

private extension SystemAgeEncryptor {
    static func findExecutableForDecryptor() -> URL? {
        [
            FileManager.default.homeDirectoryForCurrentUser.appending(path: ".local/bin/age").path,
            "/opt/homebrew/bin/age",
            "/usr/local/bin/age",
            "/usr/bin/age",
        ]
            .map { URL(filePath: $0) }
            .first { FileManager.default.isExecutableFile(atPath: $0.path) }
    }
}

public struct RemoteDeliveryReceipt: Codable, Equatable, Sendable {
    public let requestID: UUID
    public let targetID: TargetID
    public let consumerID: ConsumerID
    public let status: ReceiptStatus
    public let code: ReceiptCode

    public init(
        requestID: UUID,
        targetID: TargetID,
        consumerID: ConsumerID,
        status: ReceiptStatus,
        code: ReceiptCode
    ) {
        self.requestID = requestID
        self.targetID = targetID
        self.consumerID = consumerID
        self.status = status
        self.code = code
    }
}

public protocol RemoteAgeTransport: Sendable {
    func deliver(_ package: RemoteAgePackage, to profile: RemoteAgeProfile) async throws -> RemoteDeliveryReceipt
}

public enum RemoteHostCheckStatus: String, Codable, Sendable {
    case ready
}

public enum RemoteHostCheckCode: String, Codable, Sendable {
    case hostReady
}

public struct RemoteHostCheckReceipt: Codable, Equatable, Sendable {
    public static let currentSchemaVersion = 1

    public let schemaVersion: Int
    public let targetID: TargetID
    public let status: RemoteHostCheckStatus
    public let code: RemoteHostCheckCode

    public init(
        schemaVersion: Int,
        targetID: TargetID,
        status: RemoteHostCheckStatus,
        code: RemoteHostCheckCode
    ) {
        self.schemaVersion = schemaVersion
        self.targetID = targetID
        self.status = status
        self.code = code
    }

    public func validate(expectedTargetID: TargetID) throws {
        guard schemaVersion == Self.currentSchemaVersion,
              targetID == expectedTargetID,
              status == .ready,
              code == .hostReady else {
            throw KeyCourierError.ageOperationFailed
        }
    }
}

public protocol RemoteHostChecking: Sendable {
    func check(_ profile: RemoteAgeProfile) async throws -> RemoteHostCheckReceipt
}

public struct SSHRemoteHostChecker: RemoteHostChecking, Sendable {
    public init() {}

    public func check(_ profile: RemoteAgeProfile) async throws -> RemoteHostCheckReceipt {
        try await Task.detached(priority: .userInitiated) {
            let process = Process()
            process.executableURL = URL(filePath: "/usr/bin/ssh")
            process.arguments = [
                "-T",
                "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=yes",
                "-o", "ConnectTimeout=10",
                "-o", "ServerAliveInterval=10",
                "-o", "ServerAliveCountMax=1",
                profile.sshAlias,
                profile.helperPath,
                "check",
            ]
            let output = Pipe()
            process.standardInput = FileHandle.nullDevice
            process.standardOutput = output
            process.standardError = FileHandle.nullDevice
            do {
                try process.run()
                let response = output.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                guard process.terminationStatus == 0,
                      !response.isEmpty,
                      response.count <= 8 * 1024 else {
                    throw KeyCourierError.ageOperationFailed
                }
                let receipt = try JSONDecoder().decode(RemoteHostCheckReceipt.self, from: response)
                try receipt.validate(expectedTargetID: profile.targetID)
                return receipt
            } catch let error as KeyCourierError {
                throw error
            } catch {
                throw KeyCourierError.ageOperationFailed
            }
        }.value
    }
}

public struct SSHRemoteAgeTransport: RemoteAgeTransport, Sendable {
    public init() {}

    public func deliver(_ package: RemoteAgePackage, to profile: RemoteAgeProfile) async throws -> RemoteDeliveryReceipt {
        let process = Process()
        process.executableURL = URL(filePath: "/usr/bin/ssh")
        process.arguments = [
            "-T",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=10",
            "-o", "ServerAliveCountMax=1",
            profile.sshAlias,
            profile.helperPath,
            "deliver"
        ]
        let input = Pipe()
        let output = Pipe()
        process.standardInput = input
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            input.fileHandleForWriting.write(try package.encoded())
            input.fileHandleForWriting.closeFile()
            let response = output.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            guard process.terminationStatus == 0, response.count <= 8 * 1024 else {
                throw KeyCourierError.ageOperationFailed
            }
            let decoder = JSONDecoder()
            let receipt = try decoder.decode(RemoteDeliveryReceipt.self, from: response)
            guard receipt.requestID == package.requestID,
                  receipt.targetID == package.targetID,
                  receipt.consumerID == package.consumerID else {
                throw KeyCourierError.ageOperationFailed
            }
            return receipt
        } catch let error as KeyCourierError {
            throw error
        } catch {
            throw KeyCourierError.ageOperationFailed
        }
    }
}

public struct RemoteAgeSecretInstaller: RequestAwareSecretInstaller, Sendable {
    private let allowlist: RemoteAgeAllowlist
    private let encryptor: any AgeEncryptor
    private let transport: any RemoteAgeTransport

    public init(
        allowlist: RemoteAgeAllowlist,
        encryptor: any AgeEncryptor,
        transport: any RemoteAgeTransport
    ) {
        self.allowlist = allowlist
        self.encryptor = encryptor
        self.transport = transport
    }

    public func install(_ secret: Data, for profile: ConsumerProfile) async throws {
        throw KeyCourierError.unsupportedDestination
    }

    public func install(_ secret: Data, for profile: ConsumerProfile, request: SecretRequest) async throws {
        guard case .remoteAge(let profileID) = profile.destination,
              let profileID = ConsumerID(rawValue: profileID),
              let remoteProfile = allowlist.profile(for: profileID),
              remoteProfile.targetID == profile.targetID,
              remoteProfile.targetID == request.targetID else {
            throw KeyCourierError.unsupportedDestination
        }
        let payload = try RemoteAgePayload(request: request, secret: secret)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        let encrypted = try await Task.detached(priority: .userInitiated) {
            try self.encryptor.encrypt(encoder.encode(payload), recipients: remoteProfile.ageRecipients)
        }.value
        let package = try RemoteAgePackage(request: request, ciphertext: encrypted)
        let receipt = try await transport.deliver(package, to: remoteProfile)
        guard receipt.status == .verified, receipt.code == .consumerVerified else {
            throw KeyCourierError.ageOperationFailed
        }
    }
}

public protocol RemoteReplayStore: Sendable {
    func claim(_ requestID: UUID) throws
}

public struct FileRemoteReplayStore: RemoteReplayStore, Sendable {
    public let root: URL

    public init(root: URL) {
        self.root = root
    }

    public func claim(_ requestID: UUID) throws {
        try SecureFileSystem.ensurePrivateDirectory(root)
        let marker = root.appending(path: "\(requestID.uuidString.lowercased()).processed")
        try SecureFileSystem.createExclusiveMarker(marker)
    }
}

public struct RemoteAgeReceiver: Sendable {
    private let allowlist: RemoteAgeAllowlist
    private let decryptor: any AgeDecryptor
    private let replayStore: any RemoteReplayStore

    public init(
        allowlist: RemoteAgeAllowlist,
        decryptor: any AgeDecryptor,
        replayStore: any RemoteReplayStore
    ) {
        self.allowlist = allowlist
        self.decryptor = decryptor
        self.replayStore = replayStore
    }

    public func receive(_ package: RemoteAgePackage, at date: Date = Date()) -> RemoteDeliveryReceipt {
        let failure = RemoteDeliveryReceipt(
            requestID: package.requestID,
            targetID: package.targetID,
            consumerID: package.consumerID,
            status: .failed,
            code: .deliveryFailed
        )
        do {
            try package.validate(at: date)
            guard let profile = allowlist.profile(for: package.consumerID),
                  profile.targetID == package.targetID else {
                return failure
            }
            try replayStore.claim(package.requestID)
            let plaintext = try decryptor.decrypt(package.ciphertext, profileID: profile.id)
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            let payload = try decoder.decode(RemoteAgePayload.self, from: plaintext)
            try payload.validate(at: date)
            guard payload.requestID == package.requestID,
                  payload.targetID == package.targetID,
                  payload.consumerID == package.consumerID,
                  abs(payload.expiresAt.timeIntervalSince(package.expiresAt)) < 1,
                  abs(payload.createdAt.timeIntervalSince(package.createdAt)) < 1 else {
                return failure
            }
            let localProfile = try profile.localConsumerProfile()
            _ = try DotenvInstaller().install(payload.secret, for: localProfile)
            return RemoteDeliveryReceipt(
                requestID: package.requestID,
                targetID: package.targetID,
                consumerID: package.consumerID,
                status: .verified,
                code: .consumerVerified
            )
        } catch {
            return failure
        }
    }
}

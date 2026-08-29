import Darwin
import Foundation
import XCTest
@testable import KeyCourierCore

final class RemoteAgeTests: XCTestCase {
    func testRemoteApprovalUsesAllowlistedProfileAndReturnsOnlyReceipt() async throws {
        let request = try makeRequest()
        let remoteProfile = try makeRemoteProfile()
        let allowlist = try RemoteAgeAllowlist(profiles: [remoteProfile])
        let transport = RecordingRemoteTransport()
        let coordinator = ApprovalCoordinator(
            secretStore: FixedSecretStore(value: Data("dummy-remote-value".utf8)),
            installer: RemoteAgeSecretInstaller(
                allowlist: allowlist,
                encryptor: FixedAgeEncryptor(),
                transport: transport
            )
        )
        let consumer = try ConsumerProfile(
            id: remoteProfile.id,
            displayName: remoteProfile.displayName,
            targetID: remoteProfile.targetID,
            destination: .remoteAge(profile: remoteProfile.id.rawValue)
        )

        let receipt = await coordinator.approve(
            request,
            consumers: [consumer],
            secrets: [metadata(for: request)]
        )

        XCTAssertEqual(receipt.status, .verified)
        XCTAssertEqual(receipt.code, .consumerVerified)
        let packageCount = await transport.packageCount()
        let package = await transport.firstPackage()
        XCTAssertEqual(packageCount, 1)
        let encoded = try package.encoded()
        XCTAssertFalse(String(decoding: encoded, as: UTF8.self).contains("dummy-remote-value"))
    }

    func testRemoteApprovalEncryptsForHostAndRecoveryRecipients() async throws {
        let request = try makeRequest()
        let remoteProfile = try makeRemoteProfile()
        let encryptor = RecordingAgeEncryptor()
        let coordinator = ApprovalCoordinator(
            secretStore: FixedSecretStore(value: Data("dummy-remote-value".utf8)),
            installer: RemoteAgeSecretInstaller(
                allowlist: try RemoteAgeAllowlist(profiles: [remoteProfile]),
                encryptor: encryptor,
                transport: RecordingRemoteTransport()
            )
        )
        let consumer = try ConsumerProfile(
            id: remoteProfile.id,
            displayName: remoteProfile.displayName,
            targetID: remoteProfile.targetID,
            destination: .remoteAge(profile: remoteProfile.id.rawValue)
        )

        _ = await coordinator.approve(
            request,
            consumers: [consumer],
            secrets: [metadata(for: request)]
        )

        XCTAssertEqual(encryptor.recipients(), remoteProfile.ageRecipients)
        XCTAssertEqual(remoteProfile.ageRecipients.count, 2)
    }

    func testReceiverValidatesExpiryAndRejectsReplayAfterAtomicInstall() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let destination = root.appending(path: "consumer.env")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try Data("EXISTING=keep\n".utf8).write(to: destination)
        let request = try makeRequest()
        let remoteProfile = try makeRemoteProfile(path: destination.path)
        let payload = try RemoteAgePayload(request: request, secret: Data("dummy-remote-value".utf8))
        let payloadData = try encode(payload)
        let receiver = RemoteAgeReceiver(
            allowlist: try RemoteAgeAllowlist(profiles: [remoteProfile]),
            decryptor: FixedAgeDecryptor(plaintext: payloadData),
            replayStore: FileRemoteReplayStore(root: root.appending(path: "replay"))
        )
        let package = try RemoteAgePackage(request: request, ciphertext: Data("age-encrypted".utf8))

        let first = receiver.receive(package, at: request.createdAt)
        let second = receiver.receive(package, at: request.createdAt)

        XCTAssertEqual(first.status, .verified)
        XCTAssertEqual(first.code, .consumerVerified)
        XCTAssertEqual(second.status, .failed)
        XCTAssertEqual(second.code, .deliveryFailed)
        XCTAssertEqual(String(decoding: try Data(contentsOf: destination), as: UTF8.self), "EXISTING=keep\nREMOTE_KEY=\"dummy-remote-value\"\n")
        XCTAssertTrue(FileManager.default.fileExists(atPath: destination.path + ".keycourier.previous"))
    }

    private func metadata(for request: SecretRequest) -> SecretMetadata {
        SecretMetadata(
            secretID: request.secretID,
            displayName: "Remote test credential",
            kind: .apiKey
        )
    }

    func testReceiverRejectsExpiredPackageWithoutDecrypting() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let request = try makeRequest(createdAt: Date(timeIntervalSince1970: 1), expiresAt: Date(timeIntervalSince1970: 2))
        let remoteProfile = try makeRemoteProfile()
        let decryptor = RecordingAgeDecryptor(plaintext: Data())
        let receiver = RemoteAgeReceiver(
            allowlist: try RemoteAgeAllowlist(profiles: [remoteProfile]),
            decryptor: decryptor,
            replayStore: FileRemoteReplayStore(root: root.appending(path: "replay"))
        )
        let package = try RemoteAgePackage(request: request, ciphertext: Data("ciphertext".utf8))

        let receipt = receiver.receive(package, at: Date(timeIntervalSince1970: 3))

        XCTAssertEqual(receipt.status, .failed)
        XCTAssertEqual(decryptor.decryptCount, 0)
    }

    func testRemoteProfileStoreRoundTripsOnlyPublicRoutingData() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let profile = try makeRemoteProfile()
        let store = FileRemoteAgeProfileStore(root: root)

        try store.save([profile])

        XCTAssertEqual(try store.profiles(), [profile])
        let encoded = try Data(contentsOf: root.appending(path: "remote-profiles.json"))
        let text = String(decoding: encoded, as: UTF8.self)
        XCTAssertFalse(text.lowercased().contains("identity"))
        XCTAssertFalse(text.lowercased().contains("private"))
    }

    func testSafeConnectionReceiptAcceptsOnlyMatchingReadyHost() throws {
        let targetID = try TargetID(validating: "mac-mini")
        let receipt = RemoteHostCheckReceipt(
            schemaVersion: 1,
            targetID: targetID,
            status: .ready,
            code: .hostReady
        )

        XCTAssertNoThrow(try receipt.validate(expectedTargetID: targetID))
        XCTAssertThrowsError(
            try receipt.validate(expectedTargetID: TargetID(validating: "vps"))
        )
    }

    func testSafeConnectionReceiptContainsNoSensitiveRoutingFields() throws {
        let receipt = RemoteHostCheckReceipt(
            schemaVersion: 1,
            targetID: try TargetID(validating: "vps"),
            status: .ready,
            code: .hostReady
        )

        let encoded = try JSONEncoder().encode(receipt)
        let text = String(decoding: encoded, as: UTF8.self).lowercased()

        for forbidden in ["secret", "recipient", "identity", "path", "consumer"] {
            XCTAssertFalse(text.contains(forbidden))
        }
    }

    private func makeRequest(createdAt: Date = Date(), expiresAt: Date? = nil) throws -> SecretRequest {
        try SecretRequest(
            client: .codex,
            secretID: SecretID(validating: "remote-api"),
            targetID: TargetID(validating: "remote-mac"),
            consumerID: ConsumerID(validating: "remote-example"),
            reason: "Configure the approved remote example consumer",
            createdAt: createdAt,
            expiresAt: expiresAt ?? createdAt.addingTimeInterval(900)
        )
    }

    private func makeRemoteProfile(path: String = "/tmp/keycourier-remote-example.env") throws -> RemoteAgeProfile {
        try RemoteAgeProfile(
            id: ConsumerID(validating: "remote-example"),
            displayName: "Remote example",
            targetID: TargetID(validating: "remote-mac"),
            sshAlias: "test-host",
            helperPath: "/Users/example/.local/libexec/keycourier-remote-age",
            ageRecipients: [
                "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
                "age1rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr",
            ],
            consumer: .dotenv(path: path, variable: "REMOTE_KEY")
        )
    }

    private func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(value)
    }
}

private struct FixedSecretStore: SecretStore {
    let value: Data

    func save(_ secret: Data, id: SecretID) async throws {}
    func read(id: SecretID, reason: String) async throws -> Data? { value }
    func delete(id: SecretID, reason: String) async throws {}
}

private struct FixedAgeEncryptor: AgeEncryptor {
    func encrypt(_ plaintext: Data, recipients: [String]) throws -> Data {
        Data("age-encrypted".utf8)
    }
}

private final class RecordingAgeEncryptor: AgeEncryptor, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String] = []

    func encrypt(_ plaintext: Data, recipients: [String]) throws -> Data {
        lock.lock()
        values = recipients
        lock.unlock()
        return Data("age-encrypted".utf8)
    }

    func recipients() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return values
    }
}

private struct FixedAgeDecryptor: AgeDecryptor {
    let plaintext: Data

    func decrypt(_ ciphertext: Data, profileID: ConsumerID) throws -> Data {
        plaintext
    }
}

private actor RecordingRemoteTransport: RemoteAgeTransport {
    var packages: [RemoteAgePackage] = []

    func packageCount() -> Int { packages.count }
    func firstPackage() -> RemoteAgePackage { packages[0] }

    func deliver(_ package: RemoteAgePackage, to profile: RemoteAgeProfile) async throws -> RemoteDeliveryReceipt {
        packages.append(package)
        return RemoteDeliveryReceipt(
            requestID: package.requestID,
            targetID: package.targetID,
            consumerID: package.consumerID,
            status: .verified,
            code: .consumerVerified
        )
    }
}

private final class RecordingAgeDecryptor: AgeDecryptor, @unchecked Sendable {
    let plaintext: Data
    private let lock = NSLock()
    private var count = 0

    init(plaintext: Data) {
        self.plaintext = plaintext
    }

    var decryptCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return count
    }

    func decrypt(_ ciphertext: Data, profileID: ConsumerID) throws -> Data {
        lock.lock()
        count += 1
        lock.unlock()
        return plaintext
    }
}

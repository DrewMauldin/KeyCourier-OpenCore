import XCTest
@testable import KeyCourierCore

final class ApprovalCoordinatorTests: XCTestCase {
    func testApprovalInstallsDummyValueAndReturnsOnlyAReceipt() async throws {
        let secretID = try SecretID(validating: "example-api")
        let request = try makeRequest(secretID: secretID)
        let profile = try makeProfile()
        let vault = FakeSecretStore(values: [secretID: Data("dummy-not-a-real-secret".utf8)])
        let installer = RecordingInstaller()
        let coordinator = ApprovalCoordinator(secretStore: vault, installer: installer)
        let metadata = makeMetadata(secretID: secretID)

        let receipt = await coordinator.approve(
            request,
            consumers: [profile],
            secrets: [metadata]
        )

        XCTAssertEqual(receipt.status, .verified)
        XCTAssertEqual(receipt.code, .consumerVerified)
        let installCount = await installer.installCount
        XCTAssertEqual(installCount, 1)
    }

    func testApprovalFailsClosedWhenConsumerIsNotAllowlisted() async throws {
        let secretID = try SecretID(validating: "example-api")
        let request = try makeRequest(secretID: secretID)
        let vault = FakeSecretStore(values: [secretID: Data("dummy-not-a-real-secret".utf8)])
        let installer = RecordingInstaller()
        let coordinator = ApprovalCoordinator(secretStore: vault, installer: installer)
        let metadata = makeMetadata(secretID: secretID)

        let receipt = await coordinator.approve(request, consumers: [], secrets: [metadata])

        XCTAssertEqual(receipt.status, .failed)
        XCTAssertEqual(receipt.code, .consumerMissing)
        let installCount = await installer.installCount
        XCTAssertEqual(installCount, 0)
    }

    func testApprovalFailsClosedWhenSecretIsMissing() async throws {
        let request = try makeRequest(secretID: SecretID(validating: "missing-api"))
        let coordinator = ApprovalCoordinator(
            secretStore: FakeSecretStore(values: [:]),
            installer: RecordingInstaller()
        )

        let receipt = await coordinator.approve(
            request,
            consumers: [try makeProfile()],
            secrets: [makeMetadata(secretID: request.secretID)]
        )

        XCTAssertEqual(receipt.status, .failed)
        XCTAssertEqual(receipt.code, .secretMissing)
    }

    func testApprovalRejectsExpiredCredentialBeforeReadingKeychain() async throws {
        let now = Date()
        let secretID = try SecretID(validating: "expired-api")
        let request = try makeRequest(secretID: secretID)
        let vault = FakeSecretStore(values: [secretID: Data("dummy-not-a-real-secret".utf8)])
        let installer = RecordingInstaller()
        let coordinator = ApprovalCoordinator(secretStore: vault, installer: installer)
        let metadata = SecretMetadata(
            secretID: secretID,
            displayName: "Expired API",
            kind: .apiKey,
            createdAt: now.addingTimeInterval(-600),
            updatedAt: now.addingTimeInterval(-600),
            expiresAt: now.addingTimeInterval(-1)
        )

        let receipt = await coordinator.approve(
            request,
            consumers: [try makeProfile()],
            secrets: [metadata],
            at: now
        )

        XCTAssertEqual(receipt.status, .failed)
        XCTAssertEqual(receipt.code, .secretExpired)
        let readCount = await vault.readCount
        let installCount = await installer.installCount
        XCTAssertEqual(readCount, 0)
        XCTAssertEqual(installCount, 0)
    }

    private func makeRequest(secretID: SecretID) throws -> SecretRequest {
        try SecretRequest(
            client: .codex,
            secretID: secretID,
            targetID: TargetID(validating: "this-mac"),
            consumerID: ConsumerID(validating: "local-example"),
            reason: "Configure the approved example consumer"
        )
    }

    private func makeProfile() throws -> ConsumerProfile {
        try ConsumerProfile(
            id: ConsumerID(validating: "local-example"),
            displayName: "Local example",
            targetID: TargetID(validating: "this-mac"),
            destination: .dotenv(path: "/tmp/keycourier-example.env", variable: "EXAMPLE_KEY")
        )
    }

    private func makeMetadata(secretID: SecretID) -> SecretMetadata {
        SecretMetadata(secretID: secretID, displayName: "Example API", kind: .apiKey)
    }
}

private actor FakeSecretStore: SecretStore {
    private let values: [SecretID: Data]
    private(set) var readCount = 0

    init(values: [SecretID: Data]) {
        self.values = values
    }

    func save(_ secret: Data, id: SecretID) async throws {}

    func read(id: SecretID, reason: String) async throws -> Data? {
        readCount += 1
        return values[id]
    }

    func delete(id: SecretID, reason: String) async throws {}
}

private actor RecordingInstaller: SecretInstaller {
    private(set) var installCount = 0

    func install(_ secret: Data, for profile: ConsumerProfile) async throws {
        installCount += 1
    }
}

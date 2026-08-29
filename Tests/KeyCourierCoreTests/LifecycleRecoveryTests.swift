import XCTest
@testable import KeyCourierCore

final class LifecycleRecoveryTests: XCTestCase {
    func testLegacyMetadataDecodesWithSafeDefaults() throws {
        let json = """
        {
          "secretID": "example-api",
          "displayName": "Example API",
          "kind": "apiKey",
          "createdAt": 0,
          "updatedAt": 0
        }
        """
        let metadata = try JSONDecoder().decode(SecretMetadata.self, from: Data(json.utf8))

        XCTAssertNil(metadata.ownerName)
        XCTAssertNil(metadata.projectName)
        XCTAssertNil(metadata.rotationDueAt)
        XCTAssertFalse(metadata.allowsTelegramApproval)
    }

    func testLifecyclePrioritisesExpiryAndRotationWarnings() throws {
        let now = Date()
        let expired = SecretMetadata(
            secretID: try SecretID(validating: "expired"),
            displayName: "Expired",
            kind: .token,
            expiresAt: now.addingTimeInterval(-1)
        )
        let due = SecretMetadata(
            secretID: try SecretID(validating: "rotation-due"),
            displayName: "Rotation due",
            kind: .apiKey,
            rotationDueAt: now.addingTimeInterval(-1)
        )

        XCTAssertEqual(expired.lifecycleStatus(at: now), .expired)
        XCTAssertEqual(due.lifecycleStatus(at: now), .rotationDue)
    }

    func testDotenvImportProducesIdentifierOnlyDraftMetadata() throws {
        let drafts = try DotenvSecretImporter.parse(Data("API_TOKEN=dummy-value\nexport DB_PASSWORD='dummy-password'\n".utf8))

        XCTAssertEqual(drafts.map(\.id.rawValue), ["api-token", "db-password"])
        XCTAssertEqual(drafts.map(\.displayName), ["Api Token", "Db Password"])
        XCTAssertEqual(String(data: drafts[0].value, encoding: .utf8), "dummy-value")
    }

    func testRecoveryBundleRoundTripsWithoutChangingMetadata() throws {
        let metadata = SecretMetadata(
            secretID: try SecretID(validating: "example-api"),
            displayName: "Example API",
            kind: .apiKey,
            ownerName: "Owner",
            projectName: "Example",
            environmentName: "Test",
            allowsTelegramApproval: true
        )
        let bundle = try SecretBackupBundle(records: [
            SecretBackupRecord(metadata: metadata, secret: Data("dummy-value".utf8)),
        ])

        let restored = try SecretBackupBundle.decode(bundle.encoded())
        XCTAssertEqual(restored.schemaVersion, bundle.schemaVersion)
        XCTAssertEqual(restored.records.map(\.metadata.id), [metadata.id])
        XCTAssertEqual(restored.records.map(\.metadata.projectName), ["Example"])
        XCTAssertEqual(restored.records.map(\.metadata.allowsTelegramApproval), [true])
        XCTAssertEqual(restored.records.map(\.secret), [Data("dummy-value".utf8)])
    }
}

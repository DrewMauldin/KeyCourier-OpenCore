import Darwin
import XCTest
@testable import KeyCourierCore

final class MetadataStoreTests: XCTestCase {
    func testMetadataPersistsWithoutASecretBearingField() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = FileMetadataStore(root: root)
        let metadata = SecretMetadata(
            secretID: try SecretID(validating: "example-api"),
            displayName: "Example API",
            kind: .apiKey
        )
        let profile = try ConsumerProfile(
            id: ConsumerID(validating: "local-example"),
            displayName: "Local example",
            targetID: TargetID(validating: "this-mac"),
            destination: .dotenv(path: "/tmp/keycourier-example.env", variable: "EXAMPLE_KEY")
        )

        try store.save(metadata)
        try store.save(profile)

        XCTAssertEqual(try store.secrets(), [metadata])
        XCTAssertEqual(try store.consumers(), [profile])
        let files = try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)
        for file in files {
            let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [[String: Any]])
            let keys = Set(object.flatMap(\.keys).map { $0.lowercased() })
            XCTAssertFalse(keys.contains("value"))
            XCTAssertFalse(keys.contains("password"))
            XCTAssertFalse(keys.contains("token"))
            XCTAssertEqual(try mode(of: file) & 0o777, 0o600)
        }
    }

    func testMetadataPersistsMaterialKindAndLegacyDefaultsToSingle() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = FileMetadataStore(root: root)
        let metadata = SecretMetadata(
            secretID: try SecretID(validating: "example-login"),
            displayName: "Example login",
            kind: .password,
            materialKind: .usernamePassword
        )

        try store.save(metadata)
        XCTAssertEqual(try store.secrets().first?.materialKind, .usernamePassword)

        var legacyObject = try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(metadata)) as? [String: Any]
        )
        legacyObject.removeValue(forKey: "materialKind")
        let legacyData = try JSONSerialization.data(withJSONObject: legacyObject)
        let legacy = try JSONDecoder().decode(SecretMetadata.self, from: legacyData)
        XCTAssertEqual(legacy.materialKind, .single)
    }

    func testStoreMetadataMigrationPreservesIDsButDisablesRemoteApproval() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let legacyRoot = root.appending(path: "StoreMetadata")
        let sharedRoot = root.appending(path: "Metadata")
        let legacyStore = FileMetadataStore(root: legacyRoot)
        let sharedStore = FileMetadataStore(root: sharedRoot)
        let metadata = SecretMetadata(
            secretID: try SecretID(validating: "legacy-login"),
            displayName: "Legacy login",
            kind: .password,
            materialKind: .usernamePassword,
            allowsTelegramApproval: true,
            allowsCompanionApproval: true
        )

        try legacyStore.save(metadata)
        XCTAssertEqual(try sharedStore.migrateSecretsIfEmpty(from: legacyStore), 1)
        let migrated = try XCTUnwrap(try sharedStore.secrets().first)
        XCTAssertEqual(migrated.id, metadata.id)
        XCTAssertEqual(migrated.materialKind, metadata.materialKind)
        XCTAssertFalse(migrated.allowsTelegramApproval)
        XCTAssertFalse(migrated.allowsCompanionApproval)
        XCTAssertEqual(try sharedStore.migrateSecretsIfEmpty(from: legacyStore), 0)
    }

    func testRegisterMissingConsumersIsIdempotentAndPreservesCollisions() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = FileMetadataStore(root: root)
        let collidingMacMini = try ConsumerProfile(
            id: ConsumerID(validating: "mac-mini"),
            displayName: "Existing profile",
            targetID: TargetID(validating: "this-mac"),
            destination: .dotenv(path: "/tmp/existing.env", variable: "EXISTING_KEY")
        )
        try store.save(collidingMacMini)

        let builtIns = try GuidedDestination.allCases.map { try $0.consumerProfile() }
        try store.registerMissingConsumers(builtIns)
        try store.registerMissingConsumers(builtIns)

        let consumers = try store.consumers()
        XCTAssertEqual(consumers.count, 4)
        XCTAssertEqual(
            consumers.first(where: { $0.id.rawValue == "this-mac" }),
            try GuidedDestination.thisMac.consumerProfile()
        )
        XCTAssertEqual(consumers.first(where: { $0.id.rawValue == "mac-mini" }), collidingMacMini)
        XCTAssertEqual(
            consumers.first(where: { $0.id.rawValue == "vps" }),
            try GuidedDestination.vps.consumerProfile()
        )
        XCTAssertEqual(
            consumers.first(where: { $0.id.rawValue == "cloud-memory-projection" }),
            try GuidedDestination.cloudMemoryProjection.consumerProfile()
        )
    }

    private func mode(of url: URL) throws -> mode_t {
        var info = stat()
        guard lstat(url.path, &info) == 0 else { throw POSIXError(.ENOENT) }
        return info.st_mode
    }
}

import XCTest
@testable import KeyCourierCore

final class CompanionConfigurationStoreTests: XCTestCase {
    func testConfigurationRoundTripsTrustedDeviceAndReplayMarkers() throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "keycourier-companion-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let store = FileCompanionConfigurationStore(root: root)
        let keys = CompanionCrypto.generatePrivateKeys()
        let registration = try CompanionCrypto.registration(
            deviceID: UUID(),
            deviceName: "Owner's iPhone",
            keys: keys
        )

        let accountIdentifier = "account-a"
        var configuration = try store.trust(
            registration,
            accountIdentifier: accountIdentifier
        )
        let decisionID = UUID()
        let envelopeID = UUID()
        configuration = try store.markDecisionProcessed(decisionID)
        configuration = try store.markEnvelopeProcessed(envelopeID)

        XCTAssertTrue(configuration.isEnabled)
        XCTAssertEqual(configuration.trustedDevice?.id, registration.id)
        XCTAssertEqual(configuration.accountIdentifier, accountIdentifier)
        XCTAssertTrue(configuration.isBound(to: accountIdentifier))
        XCTAssertFalse(configuration.isBound(to: "account-b"))
        XCTAssertEqual(configuration.processedDecisionIDs, [decisionID])
        XCTAssertEqual(configuration.processedEnvelopeIDs, [envelopeID])
        XCTAssertEqual(try store.configuration(), configuration)
    }

    func testLegacyTrustedConfigurationWithoutAccountBindingFailsClosed() throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "keycourier-companion-legacy-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let store = FileCompanionConfigurationStore(root: root)
        let registration = try CompanionCrypto.registration(
            deviceID: UUID(),
            deviceName: "Owner's iPhone",
            keys: CompanionCrypto.generatePrivateKeys()
        )

        let legacy = try store.trust(registration)
        XCTAssertNil(legacy.accountIdentifier)
        XCTAssertFalse(legacy.isBound(to: "account-a"))
        XCTAssertNil(try store.configuration().accountIdentifier)

        let reset = try store.requireRePair()
        XCTAssertNil(reset.trustedDevice)
        XCTAssertNil(reset.accountIdentifier)
    }
}

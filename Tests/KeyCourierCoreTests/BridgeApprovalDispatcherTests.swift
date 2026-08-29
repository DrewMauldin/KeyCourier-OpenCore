import CryptoKit
import Foundation
import XCTest
@testable import KeyCourierCore

final class BridgeApprovalDispatcherTests: XCTestCase {
    func testApprovalAuthenticatesBeforeReadingAndPublishesOnlyCiphertext() async throws {
        let fixture = try Fixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let events = EventRecorder()
        let dispatcher = BridgeApprovalDispatcher(
            secretStore: FakeSecretStore(secret: fixture.secret, events: events),
            ownerAuthorizer: FakeAuthorizer(events: events)
        )

        let command = try await dispatcher.approve(
            fixture.signedRequest,
            pinnedBridge: fixture.pinnedBridge,
            storeIdentity: fixture.storeIdentity,
            secrets: [fixture.metadata],
            queue: fixture.queue,
            at: fixture.now.addingTimeInterval(1)
        )

        let recordedEvents = await events.values
        XCTAssertEqual(recordedEvents, ["authorize", "read"])
        XCTAssertEqual(command.action, .deliver)
        XCTAssertEqual(
            try BridgeCrypto.openDeliveryCommand(
                command,
                recipientPrivateKey: fixture.bridgeIdentity.keys.keyAgreementPrivateKey,
                appSigningPublicKey: fixture.storeSigningPublicKey,
                expectedBridgeID: fixture.bridgeIdentity.id,
                expectedRequestDigest: try BridgeCrypto.requestDigest(for: fixture.signedRequest.request),
                at: fixture.now.addingTimeInterval(2)
            ),
            fixture.secret
        )
        let commandData = try Data(contentsOf: fixture.root.appending(path: "Commands/\(command.commandID.uuidString.lowercased()).command.json"))
        XCTAssertFalse(String(decoding: commandData, as: UTF8.self).contains(String(decoding: fixture.secret, as: UTF8.self)))
        XCTAssertTrue(try fixture.queue.pendingRequests(at: fixture.now.addingTimeInterval(2)).isEmpty)
    }

    func testInvalidRequestFailsBeforeAuthenticationOrKeychainRead() async throws {
        let fixture = try Fixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let events = EventRecorder()
        let dispatcher = BridgeApprovalDispatcher(
            secretStore: FakeSecretStore(secret: fixture.secret, events: events),
            ownerAuthorizer: FakeAuthorizer(events: events)
        )
        var altered = fixture.signedRequest
        altered.signature[0] ^= 0xff

        await XCTAssertThrowsErrorAsync(
            try await dispatcher.approve(
                altered,
                pinnedBridge: fixture.pinnedBridge,
                storeIdentity: fixture.storeIdentity,
                secrets: [fixture.metadata],
                queue: fixture.queue,
                at: fixture.now.addingTimeInterval(1)
            )
        ) { error in
            XCTAssertEqual(error as? BridgeProtocolError, .invalidSignature)
        }
        let recordedEvents = await events.values
        XCTAssertEqual(recordedEvents, [])
    }

    func testPairCredentialCanBeEncryptedForASeparatelyConfiguredLoginDestination() async throws {
        let fixture = try Fixture(materialKind: .usernamePassword)
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let events = EventRecorder()
        let dispatcher = BridgeApprovalDispatcher(
            secretStore: FakeSecretStore(secret: fixture.secret, events: events),
            ownerAuthorizer: FakeAuthorizer(events: events)
        )

        _ = try await dispatcher.approve(
            fixture.signedRequest,
            pinnedBridge: fixture.pinnedBridge,
            storeIdentity: fixture.storeIdentity,
            secrets: [fixture.metadata],
            queue: fixture.queue,
            at: fixture.now.addingTimeInterval(1)
        )
        let recordedEvents = await events.values
        XCTAssertEqual(recordedEvents, ["authorize", "read"])
    }

    func testCompanionApprovalSkipsMacAuthenticationForEligibleCredential() async throws {
        let fixture = try Fixture(allowsCompanionApproval: true)
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let events = EventRecorder()
        let dispatcher = BridgeApprovalDispatcher(
            secretStore: FakeSecretStore(secret: fixture.secret, events: events),
            ownerAuthorizer: FakeAuthorizer(events: events)
        )

        _ = try await dispatcher.approveFromCompanion(
            fixture.signedRequest,
            pinnedBridge: fixture.pinnedBridge,
            storeIdentity: fixture.storeIdentity,
            secrets: [fixture.metadata],
            queue: fixture.queue,
            at: fixture.now.addingTimeInterval(1)
        )

        let recordedEvents = await events.values
        XCTAssertEqual(recordedEvents, ["read"])
    }

    func testCompanionApprovalRejectsCredentialWithoutEligibilityBeforeReading() async throws {
        let fixture = try Fixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let events = EventRecorder()
        let dispatcher = BridgeApprovalDispatcher(
            secretStore: FakeSecretStore(secret: fixture.secret, events: events),
            ownerAuthorizer: FakeAuthorizer(events: events)
        )

        await XCTAssertThrowsErrorAsync(
            try await dispatcher.approveFromCompanion(
                fixture.signedRequest,
                pinnedBridge: fixture.pinnedBridge,
                storeIdentity: fixture.storeIdentity,
                secrets: [fixture.metadata],
                queue: fixture.queue,
                at: fixture.now.addingTimeInterval(1)
            )
        ) { error in
            XCTAssertEqual(error as? BridgeProtocolError, .invalidRecord)
        }

        let recordedEvents = await events.values
        XCTAssertEqual(recordedEvents, [])
    }

    func testExistingDenialCannotBeReportedAsAnApproval() async throws {
        let fixture = try Fixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let events = EventRecorder()
        let dispatcher = BridgeApprovalDispatcher(
            secretStore: FakeSecretStore(secret: fixture.secret, events: events),
            ownerAuthorizer: FakeAuthorizer(events: events)
        )
        _ = try dispatcher.deny(
            fixture.signedRequest,
            pinnedBridge: fixture.pinnedBridge,
            storeIdentity: fixture.storeIdentity,
            queue: fixture.queue,
            at: fixture.now.addingTimeInterval(1)
        )

        await XCTAssertThrowsErrorAsync(
            try await dispatcher.approve(
                fixture.signedRequest,
                pinnedBridge: fixture.pinnedBridge,
                storeIdentity: fixture.storeIdentity,
                secrets: [fixture.metadata],
                queue: fixture.queue,
                at: fixture.now.addingTimeInterval(2)
            )
        ) { error in
            XCTAssertEqual(error as? BridgeProtocolError, .conflictingRecord)
        }
        let recordedEvents = await events.values
        XCTAssertEqual(recordedEvents, [])
    }

    private actor EventRecorder {
        private(set) var values: [String] = []
        func append(_ value: String) { values.append(value) }
    }

    private struct FakeAuthorizer: OwnerPresenceAuthorizing {
        let events: EventRecorder
        func authorize(reason: String) async throws { await events.append("authorize") }
    }

    private struct FakeSecretStore: SecretStore {
        let secret: Data
        let events: EventRecorder
        func save(_ secret: Data, id: SecretID) async throws {}
        func read(id: SecretID, reason: String) async throws -> Data? {
            await events.append("read")
            return secret
        }
        func delete(id: SecretID, reason: String) async throws {}
    }

    private struct Fixture {
        let root = FileManager.default.temporaryDirectory.appending(path: "keycourier-approval-\(UUID().uuidString)")
        let now = Date()
        let queue: BridgeQueue
        let bridgeIdentity: BridgeIdentity
        let storeIdentity: BridgeIdentity
        let pinnedBridge: BridgePinnedPeer
        let signedRequest: SignedBridgeRequest
        let metadata: SecretMetadata
        let secret: Data
        let storeSigningPublicKey: Data

        init(
            materialKind: SecretMaterialKind = .single,
            allowsCompanionApproval: Bool = false
        ) throws {
            secret = if materialKind == .usernamePassword {
                try CompanionCredentialMaterial.usernamePassword(
                    username: "owner@example.com",
                    password: Data("approval-canary-never-persist".utf8)
                ).deliveryData()
            } else {
                Data("approval-canary-never-persist".utf8)
            }
            queue = BridgeQueue(root: root)
            bridgeIdentity = BridgeIdentity(id: UUID(), keys: BridgeCrypto.generatePrivateKeys())
            storeIdentity = BridgeIdentity(id: UUID(), keys: BridgeCrypto.generatePrivateKeys())
            let bridgeSigningPublicKey = try Curve25519.Signing.PrivateKey(
                rawRepresentation: bridgeIdentity.keys.signingPrivateKey
            ).publicKey.rawRepresentation
            let bridgeAgreementPublicKey = try Curve25519.KeyAgreement.PrivateKey(
                rawRepresentation: bridgeIdentity.keys.keyAgreementPrivateKey
            ).publicKey.rawRepresentation
            storeSigningPublicKey = try Curve25519.Signing.PrivateKey(
                rawRepresentation: storeIdentity.keys.signingPrivateKey
            ).publicKey.rawRepresentation
            pinnedBridge = try BridgePinnedPeer(
                bridgeID: bridgeIdentity.id,
                signingPublicKey: bridgeSigningPublicKey,
                keyAgreementPublicKey: bridgeAgreementPublicKey,
                registrationDigest: Data(repeating: 3, count: SHA256.byteCount)
            )
            let request = try SecretRequest(
                client: .codex,
                secretID: SecretID(validating: "example-api"),
                targetID: TargetID(validating: "this-mac"),
                consumerID: ConsumerID(validating: "selected-env"),
                reason: "Install the approved credential",
                createdAt: now,
                expiresAt: now.addingTimeInterval(900)
            )
            signedRequest = try BridgeCrypto.sign(
                SignedBridgeRequest(
                    bridgeID: bridgeIdentity.id,
                    request: request,
                    requestNonce: Data(repeating: 4, count: 32)
                ),
                privateKey: bridgeIdentity.keys.signingPrivateKey
            )
            metadata = SecretMetadata(
                secretID: request.secretID,
                displayName: "Example API",
                kind: .apiKey,
                materialKind: materialKind,
                createdAt: now,
                updatedAt: now,
                allowsCompanionApproval: allowsCompanionApproval
            )
            _ = try queue.enqueue(signedRequest)
        }
    }
}

private func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    _ handler: (Error) -> Void
) async {
    do {
        _ = try await expression()
        XCTFail("Expected an error")
    } catch {
        handler(error)
    }
}

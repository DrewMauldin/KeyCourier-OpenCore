import CryptoKit
import Foundation
import XCTest
@testable import KeyCourierCore

final class BridgeDeliveryTests: XCTestCase {
    func testProcessorInstallsOnceAndReturnsASignedContentFreeReceipt() async throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let fixture = try Fixture(root: root)
        let installer = RecordingInstaller()
        let processor = BridgeCommandProcessor(
            queue: fixture.queue,
            identity: fixture.bridgeIdentity,
            pinnedStore: fixture.pinnedStore,
            profile: { id in id == fixture.profile.id ? fixture.profile : nil },
            install: { secret, profile in await installer.install(secret, for: profile) }
        )
        _ = try fixture.queue.enqueue(fixture.command)

        let first = try await processor.process(fixture.command, at: fixture.now.addingTimeInterval(1))
        let second = try await processor.process(fixture.command, at: fixture.now.addingTimeInterval(2))

        XCTAssertEqual(first, second)
        let installCount = await installer.installCount
        let lastSecret = await installer.lastSecret
        XCTAssertEqual(installCount, 1)
        XCTAssertEqual(lastSecret, fixture.secret)
        XCTAssertNoThrow(
            try BridgeCrypto.verify(
                first,
                signingPublicKey: fixture.bridgeSigningPublicKey,
                expectedBridgeID: fixture.bridgeIdentity.id,
                expectedCommandID: fixture.command.commandID,
                expectedRequestID: fixture.request.id,
                expectedRequestDigest: fixture.command.requestDigest
            )
        )
        XCTAssertEqual(first.receipt.status, .verified)
        XCTAssertEqual(first.receipt.code, .consumerVerified)

        let receiptURL = root.appending(path: "Receipts/\(fixture.command.commandID.uuidString.lowercased()).receipt.json")
        let persisted = try String(contentsOf: receiptURL, encoding: .utf8)
        XCTAssertFalse(persisted.contains(String(decoding: fixture.secret, as: UTF8.self)))
    }

    func testClaimedCommandWithoutReceiptIsNotRetried() async throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let fixture = try Fixture(root: root)
        let installer = RecordingInstaller()
        let processor = BridgeCommandProcessor(
            queue: fixture.queue,
            identity: fixture.bridgeIdentity,
            pinnedStore: fixture.pinnedStore,
            profile: { _ in fixture.profile },
            install: { secret, profile in await installer.install(secret, for: profile) }
        )
        _ = try fixture.queue.enqueue(fixture.command)
        XCTAssertEqual(try fixture.queue.claimCommand(fixture.command, at: fixture.now), .claimed)

        await XCTAssertThrowsErrorAsync(
            try await processor.process(fixture.command, at: fixture.now.addingTimeInterval(1))
        ) { error in
            XCTAssertEqual(error as? BridgeProtocolError, .claimExists)
        }
        let installCount = await installer.installCount
        XCTAssertEqual(installCount, 0)
    }

    func testDestinationMismatchProducesTerminalSignedReceiptWithoutDecryption() async throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let fixture = try Fixture(root: root)
        let wrongProfile = try ConsumerProfile(
            id: fixture.profile.id,
            displayName: "Wrong target",
            targetID: TargetID(validating: "another-target"),
            destination: .dotenv(path: root.appending(path: "wrong.env").path, variable: "API_KEY")
        )
        let installer = RecordingInstaller()
        let processor = BridgeCommandProcessor(
            queue: fixture.queue,
            identity: fixture.bridgeIdentity,
            pinnedStore: fixture.pinnedStore,
            profile: { _ in wrongProfile },
            install: { secret, profile in await installer.install(secret, for: profile) }
        )
        _ = try fixture.queue.enqueue(fixture.command)

        let receipt = try await processor.process(
            fixture.command,
            at: fixture.now.addingTimeInterval(1)
        )
        let installCount = await installer.installCount
        XCTAssertEqual(installCount, 0)
        XCTAssertEqual(receipt.receipt.status, .notConfigured)
        XCTAssertEqual(receipt.receipt.code, .validationFailed)
        XCTAssertNoThrow(
            try BridgeCrypto.verify(
                receipt,
                signingPublicKey: fixture.bridgeSigningPublicKey,
                expectedBridgeID: fixture.bridgeIdentity.id,
                expectedCommandID: fixture.command.commandID,
                expectedRequestID: fixture.request.id,
                expectedRequestDigest: fixture.command.requestDigest
            )
        )
        XCTAssertThrowsError(
            try fixture.queue.claimCommand(fixture.command, at: fixture.now.addingTimeInterval(2))
        )
    }

    func testMissingDestinationProducesTerminalSignedReceiptWithoutDecryption() async throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let fixture = try Fixture(root: root)
        let installer = RecordingInstaller()
        let processor = BridgeCommandProcessor(
            queue: fixture.queue,
            identity: fixture.bridgeIdentity,
            pinnedStore: fixture.pinnedStore,
            profile: { _ in nil },
            install: { secret, profile in await installer.install(secret, for: profile) }
        )
        _ = try fixture.queue.enqueue(fixture.command)

        let receipt = try await processor.process(
            fixture.command,
            at: fixture.now.addingTimeInterval(1)
        )

        let installCount = await installer.installCount
        XCTAssertEqual(installCount, 0)
        XCTAssertEqual(receipt.receipt.status, .notConfigured)
        XCTAssertEqual(receipt.receipt.code, .consumerMissing)
        XCTAssertNoThrow(
            try BridgeCrypto.verify(
                receipt,
                signingPublicKey: fixture.bridgeSigningPublicKey,
                expectedBridgeID: fixture.bridgeIdentity.id,
                expectedCommandID: fixture.command.commandID,
                expectedRequestID: fixture.request.id,
                expectedRequestDigest: fixture.command.requestDigest
            )
        )
    }

    func testUsernamePasswordDeliveryInstallsSeparateVariables() async throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let secret = try CompanionCredentialMaterial.usernamePassword(
            username: "owner@example.com",
            password: Data("pair-canary-never-log".utf8)
        ).deliveryData()
        let destination = root.appending(path: "login.env")
        let fixture = try Fixture(
            root: root,
            destination: .dotenvLogin(
                path: destination.path,
                usernameVariable: "SERVICE_USERNAME",
                passwordVariable: "SERVICE_PASSWORD"
            ),
            secret: secret
        )
        let installer = DotenvInstaller()
        let processor = BridgeCommandProcessor(
            queue: fixture.queue,
            identity: fixture.bridgeIdentity,
            pinnedStore: fixture.pinnedStore,
            profile: { _ in fixture.profile },
            install: { data, profile in
                let login = try CompanionCredentialMaterial.usernamePassword(fromDeliveryData: data)
                _ = try installer.install(
                    username: login.username,
                    password: login.password,
                    for: profile
                )
            }
        )
        _ = try fixture.queue.enqueue(fixture.command)

        let receipt = try await processor.process(
            fixture.command,
            at: fixture.now.addingTimeInterval(1)
        )

        XCTAssertEqual(receipt.receipt.status, .verified)
        let installed = try String(contentsOf: destination, encoding: .utf8)
        XCTAssertTrue(installed.contains("SERVICE_USERNAME=\"owner@example.com\""))
        XCTAssertTrue(installed.contains("SERVICE_PASSWORD=\"pair-canary-never-log\""))
    }

    func testDenyCommandProducesDeniedReceiptWithoutResolvingAProfile() async throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let fixture = try Fixture(root: root, denied: true)
        let processor = BridgeCommandProcessor(
            queue: fixture.queue,
            identity: fixture.bridgeIdentity,
            pinnedStore: fixture.pinnedStore,
            profile: { _ in XCTFail("Deny must not resolve a destination"); return nil },
            install: { _, _ in XCTFail("Deny must not install") }
        )
        _ = try fixture.queue.enqueue(fixture.command)

        let receipt = try await processor.process(fixture.command, at: fixture.now.addingTimeInterval(1))

        XCTAssertEqual(receipt.receipt.status, .denied)
        XCTAssertEqual(receipt.receipt.code, .ownerDenied)
    }

    private actor RecordingInstaller {
        private(set) var installCount = 0
        private(set) var lastSecret: Data?

        func install(_ secret: Data, for profile: ConsumerProfile) {
            installCount += 1
            lastSecret = secret
        }
    }

    private struct Fixture {
        let now = Date()
        let queue: BridgeQueue
        let bridgeIdentity: BridgeIdentity
        let pinnedStore: BridgePinnedPeer
        let request: SecretRequest
        let command: BridgeDeliveryCommand
        let profile: ConsumerProfile
        let secret: Data
        let bridgeSigningPublicKey: Data

        init(
            root: URL,
            denied: Bool = false,
            destination: ConsumerDestination? = nil,
            secret: Data = Data("delivery-canary-never-log".utf8)
        ) throws {
            self.secret = secret
            queue = BridgeQueue(root: root)
            let bridgeKeys = BridgeCrypto.generatePrivateKeys()
            let storeKeys = BridgeCrypto.generatePrivateKeys()
            bridgeIdentity = BridgeIdentity(id: UUID(), keys: bridgeKeys)
            bridgeSigningPublicKey = try Curve25519.Signing.PrivateKey(
                rawRepresentation: bridgeKeys.signingPrivateKey
            ).publicKey.rawRepresentation
            let storeSigningPublicKey = try Curve25519.Signing.PrivateKey(
                rawRepresentation: storeKeys.signingPrivateKey
            ).publicKey.rawRepresentation
            pinnedStore = try BridgePinnedPeer(
                bridgeID: bridgeIdentity.id,
                signingPublicKey: storeSigningPublicKey,
                registrationDigest: Data(repeating: 7, count: SHA256.byteCount)
            )
            request = try SecretRequest(
                client: .codex,
                secretID: SecretID(validating: "example-api"),
                targetID: TargetID(validating: "this-mac"),
                consumerID: ConsumerID(validating: "selected-env"),
                reason: "Install the approved credential",
                createdAt: now,
                expiresAt: now.addingTimeInterval(900)
            )
            profile = try ConsumerProfile(
                id: request.consumerID,
                displayName: "Selected environment",
                targetID: request.targetID,
                destination: destination ?? .dotenv(
                    path: root.appending(path: "installed.env").path,
                    variable: "API_KEY"
                )
            )
            command = if denied {
                try BridgeCrypto.makeDenyCommand(
                    request: request,
                    bridgeID: bridgeIdentity.id,
                    appSigningPrivateKey: storeKeys.signingPrivateKey,
                    createdAt: now,
                    expiresAt: request.expiresAt
                )
            } else {
                try BridgeCrypto.makeDeliveryCommand(
                    request: request,
                    bridgeID: bridgeIdentity.id,
                    recipientPublicKey: try Curve25519.KeyAgreement.PrivateKey(
                        rawRepresentation: bridgeKeys.keyAgreementPrivateKey
                    ).publicKey.rawRepresentation,
                    secret: secret,
                    appSigningPrivateKey: storeKeys.signingPrivateKey,
                    createdAt: now,
                    expiresAt: request.expiresAt
                )
            }
        }
    }

    private func temporaryRoot() -> URL {
        FileManager.default.temporaryDirectory.appending(path: "keycourier-delivery-\(UUID().uuidString)")
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

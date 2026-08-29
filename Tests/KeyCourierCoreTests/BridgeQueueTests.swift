import CryptoKit
import Darwin
import Foundation
import XCTest
@testable import KeyCourierCore

final class BridgeQueueTests: XCTestCase {
    func testQueueSupportsATrustedFilesystemAnchor() throws {
        let anchor = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: anchor) }
        try FileManager.default.createDirectory(
            at: anchor,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let queue = BridgeQueue(
            root: anchor.appending(path: "KeyCourierBridge"),
            trustedAnchor: anchor
        )
        let request = try signedRequest(keys: BridgeCrypto.generatePrivateKeys())

        _ = try queue.enqueue(request)

        XCTAssertEqual(try queue.pendingRequests().map(\.id), [request.id])
    }

    func testRequestsAreAtomicBoundedAndDuplicateContentIsIdempotent() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let queue = BridgeQueue(root: root, maximumPendingRecords: 1)
        let keys = BridgeCrypto.generatePrivateKeys()
        let now = Date()
        let request = try signedRequest(keys: keys, createdAt: now)

        let first = try queue.enqueue(request)
        let second = try queue.enqueue(request)

        XCTAssertEqual(first, second)
        XCTAssertEqual(try queue.pendingRequests().map(\.id), [request.id])
        XCTAssertEqual(mode(of: first) & 0o777, 0o600)
        XCTAssertEqual(mode(of: root.appending(path: "Requests")) & 0o777, 0o700)

        let otherRequest = try signedRequest(
            keys: keys,
            id: UUID(uuidString: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")!,
            createdAt: now
        )
        XCTAssertThrowsError(try queue.enqueue(otherRequest)) { error in
            XCTAssertEqual(error as? BridgeProtocolError, .queueLimitExceeded)
        }
    }

    func testDuplicateRequestIDWithDifferentDigestIsRejected() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let queue = BridgeQueue(root: root)
        let keys = BridgeCrypto.generatePrivateKeys()
        let id = UUID(uuidString: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")!
        let original = try signedRequest(keys: keys, id: id, reason: "First approved reason")
        let altered = try signedRequest(keys: keys, id: id, reason: "Different approved reason")

        _ = try queue.enqueue(original)
        XCTAssertThrowsError(try queue.enqueue(altered)) { error in
            XCTAssertEqual(error as? BridgeProtocolError, .conflictingRecord)
        }
    }

    func testDuplicateRequestIDWithChangedWrapperIsRejected() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let queue = BridgeQueue(root: root)
        let keys = BridgeCrypto.generatePrivateKeys()
        let original = try signedRequest(keys: keys)
        let altered = try BridgeCrypto.sign(
            SignedBridgeRequest(
                bridgeID: original.bridgeID,
                request: original.request,
                requestNonce: Data(repeating: 10, count: 32)
            ),
            privateKey: keys.signingPrivateKey
        )

        _ = try queue.enqueue(original)
        XCTAssertThrowsError(try queue.enqueue(altered)) { error in
            XCTAssertEqual(error as? BridgeProtocolError, .conflictingRecord)
        }
    }

    func testAliasedRequestFilenameIsNotEnumeratedTwice() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let queue = BridgeQueue(root: root)
        let keys = BridgeCrypto.generatePrivateKeys()
        let request = try signedRequest(keys: keys)
        let canonical = try queue.enqueue(request)
        let alias = canonical.deletingLastPathComponent().appending(
            path: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb.request.json"
        )
        try FileManager.default.copyItem(at: canonical, to: alias)

        XCTAssertEqual(try queue.pendingRequests().map(\.id), [request.id])
    }

    func testPersistedFractionalDatesRetainValidSignature() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let queue = BridgeQueue(root: root)
        let keys = BridgeCrypto.generatePrivateKeys()
        let createdAt = Date(timeIntervalSince1970: floor(Date().timeIntervalSince1970) + 0.123)
        let request = try signedRequest(keys: keys, createdAt: createdAt)

        _ = try queue.enqueue(request)
        let decoded = try XCTUnwrap(queue.pendingRequests(at: createdAt.addingTimeInterval(1)).first)

        XCTAssertNoThrow(
            try BridgeCrypto.verify(
                decoded,
                signingPublicKey: signingPublicKey(from: keys),
                expectedBridgeID: request.bridgeID,
                at: createdAt.addingTimeInterval(1)
            )
        )
    }

    func testClaimsAreExclusiveAndConflictingClaimCannotReplaceIt() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let queue = BridgeQueue(root: root)
        let keys = BridgeCrypto.generatePrivateKeys()
        let id = UUID(uuidString: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")!
        let original = try signedRequest(keys: keys, id: id, reason: "First approved reason")
        let altered = try signedRequest(keys: keys, id: id, reason: "Different approved reason")

        _ = try queue.enqueue(original)
        XCTAssertEqual(try queue.claimRequest(original), .claimed)
        XCTAssertEqual(try queue.claimRequest(original), .alreadyClaimed)
        XCTAssertThrowsError(try queue.claimRequest(altered)) { error in
            XCTAssertEqual(error as? BridgeProtocolError, .conflictingRecord)
        }
        XCTAssertTrue(try queue.pendingRequests().isEmpty)
    }

    func testClaimRejectsARecordThatWasNeverEnqueued() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let queue = BridgeQueue(root: root)
        let request = try signedRequest(keys: BridgeCrypto.generatePrivateKeys())

        XCTAssertThrowsError(try queue.claimRequest(request)) { error in
            XCTAssertEqual(error as? BridgeProtocolError, .invalidRecord)
        }
    }

    func testCompletedCommandCannotBeReenqueuedAfterCommandAndClaimExpire() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let queue = BridgeQueue(root: root)
        let bridgeKeys = BridgeCrypto.generatePrivateKeys()
        let appKeys = BridgeCrypto.generatePrivateKeys()
        let now = Date()
        let request = try signedRequest(keys: bridgeKeys, createdAt: now).request
        let command = try BridgeCrypto.makeDenyCommand(
            request: request,
            bridgeID: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!,
            appSigningPrivateKey: appKeys.signingPrivateKey,
            createdAt: now,
            expiresAt: now.addingTimeInterval(10)
        )
        let receipt = try BridgeCrypto.sign(
            SignedBridgeReceipt(
                bridgeID: command.bridgeID,
                commandID: command.commandID,
                requestDigest: command.requestDigest,
                receipt: RequestReceipt(
                    requestID: request.id,
                    status: .denied,
                    targetID: request.targetID,
                    consumerID: request.consumerID,
                    code: .ownerDenied,
                    recordedAt: now
                )
            ),
            privateKey: bridgeKeys.signingPrivateKey
        )

        _ = try queue.enqueue(command)
        XCTAssertEqual(try queue.claimCommand(command, at: now), .claimed)
        _ = try queue.record(receipt)
        try queue.removeCommand(command.commandID)
        try queue.pruneExpiredClaims(at: now.addingTimeInterval(11))

        XCTAssertThrowsError(try queue.enqueue(command)) { error in
            XCTAssertEqual(error as? BridgeProtocolError, .replayedRecord)
        }
        XCTAssertThrowsError(try queue.claimCommand(command, at: now.addingTimeInterval(1))) { error in
            XCTAssertEqual(error as? BridgeProtocolError, .replayedRecord)
        }
    }

    func testReceiptsAreRetainedThroughCommandLifetimeThenPrunedForCapacity() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let queue = BridgeQueue(root: root)
        let bridgeKeys = BridgeCrypto.generatePrivateKeys()
        let now = Date()
        let request = try signedRequest(keys: bridgeKeys, createdAt: now).request
        let receipt = try BridgeCrypto.sign(
            SignedBridgeReceipt(
                bridgeID: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!,
                commandID: UUID(),
                requestDigest: try BridgeCrypto.requestDigest(for: request),
                receipt: RequestReceipt(
                    requestID: request.id,
                    status: .denied,
                    targetID: request.targetID,
                    consumerID: request.consumerID,
                    code: .ownerDenied,
                    recordedAt: now
                )
            ),
            privateKey: bridgeKeys.signingPrivateKey
        )
        _ = try queue.record(receipt)

        try queue.pruneExpiredRecords(at: now.addingTimeInterval(24 * 60 * 60 - 1))
        XCTAssertNotNil(try queue.receipt(for: receipt.commandID))
        try queue.pruneExpiredRecords(at: now.addingTimeInterval(24 * 60 * 60 + 1))
        XCTAssertNil(try queue.receipt(for: receipt.commandID))
    }

    func testCommandAndReceiptQueuesNeverPersistTheCredentialCanary() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let queue = BridgeQueue(root: root)
        let bridgeKeys = BridgeCrypto.generatePrivateKeys()
        let appKeys = BridgeCrypto.generatePrivateKeys()
        let now = Date()
        let request = try signedRequest(keys: bridgeKeys, createdAt: now).request
        let canary = Data("bridge-queue-canary-never-persist".utf8)
        let command = try BridgeCrypto.makeDeliveryCommand(
            request: request,
            bridgeID: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!,
            recipientPublicKey: try agreementPublicKey(from: bridgeKeys),
            secret: canary,
            appSigningPrivateKey: appKeys.signingPrivateKey,
            commandID: UUID(uuidString: "33333333-3333-3333-3333-333333333333")!,
            createdAt: now,
            expiresAt: now.addingTimeInterval(900)
        )
        _ = try queue.enqueue(command)
        let receipt = RequestReceipt(
            requestID: request.id,
            status: .denied,
            targetID: request.targetID,
            consumerID: request.consumerID,
            code: .ownerDenied,
            recordedAt: now
        )
        let signedReceipt = try BridgeCrypto.sign(
            SignedBridgeReceipt(
                bridgeID: command.bridgeID,
                commandID: command.commandID,
                requestDigest: command.requestDigest,
                receipt: receipt
            ),
            privateKey: bridgeKeys.signingPrivateKey
        )
        _ = try queue.record(signedReceipt)

        if let enumerator = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil) {
            for case let file as URL in enumerator {
                guard file.hasDirectoryPath == false else { continue }
                let data = try Data(contentsOf: file)
                XCTAssertFalse(String(decoding: data, as: UTF8.self).contains(String(decoding: canary, as: UTF8.self)))
            }
        }
    }

    func testClaimExpiryIsPrunedButLiveClaimIsRetained() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let queue = BridgeQueue(root: root, maximumTotalRecords: 8)
        let keys = BridgeCrypto.generatePrivateKeys()
        let now = Date()
        let request = try signedRequest(keys: keys, createdAt: now)
        let bridgeID = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
        let appKeys = BridgeCrypto.generatePrivateKeys()
        let command = try BridgeCrypto.makeDeliveryCommand(
            request: request.request,
            bridgeID: bridgeID,
            recipientPublicKey: try agreementPublicKey(from: keys),
            secret: Data("temporary-command-secret".utf8),
            appSigningPrivateKey: appKeys.signingPrivateKey,
            createdAt: now,
            expiresAt: now.addingTimeInterval(900)
        )

        _ = try queue.enqueue(request)
        XCTAssertEqual(try queue.claimRequest(request, at: now), .claimed)
        _ = try queue.enqueue(command)
        XCTAssertEqual(try queue.claimCommand(command, at: now), .claimed)
        try queue.pruneExpiredClaims(at: now.addingTimeInterval(901))
        XCTAssertEqual(try queue.claimRequest(request, at: now.addingTimeInterval(901)), .alreadyClaimed)
    }

    func testExpiredRequestsArePrunedBeforeCapacityCheck() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let queue = BridgeQueue(root: root, maximumPendingRecords: 1)
        let keys = BridgeCrypto.generatePrivateKeys()
        let now = Date()
        let expiring = try signedRequest(
            keys: keys,
            createdAt: now.addingTimeInterval(-3_599)
        )

        _ = try queue.enqueue(expiring)
        try queue.pruneExpiredRecords(at: now.addingTimeInterval(2))

        let replacement = try signedRequest(
            keys: keys,
            id: UUID(uuidString: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")!,
            createdAt: now
        )
        XCTAssertNoThrow(try queue.enqueue(replacement))
    }

    func testUnsafeQueueDirectoryFailsClosed() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let outside = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: outside) }
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(
            at: root.appending(path: "Requests"),
            withDestinationURL: outside
        )

        XCTAssertThrowsError(try BridgeQueue(root: root).prepare()) { error in
            XCTAssertNotNil(error)
        }
    }

    func testPurgeAllRemovesQueueRecordsWithoutFollowingSubstitutedLinks() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let queue = BridgeQueue(root: root)
        let request = try signedRequest(keys: BridgeCrypto.generatePrivateKeys())
        _ = try queue.enqueue(request)
        let outside = temporaryRoot().appending(path: "outside.json")
        defer { try? FileManager.default.removeItem(at: outside.deletingLastPathComponent()) }
        try FileManager.default.createDirectory(
            at: outside.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try Data("preserve".utf8).write(to: outside)
        let link = root.appending(path: "Requests/substituted.json")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: outside)

        XCTAssertNoThrow(try queue.purgeAll())
        XCTAssertTrue(FileManager.default.fileExists(atPath: outside.path))
        XCTAssertEqual(try String(contentsOf: outside, encoding: .utf8), "preserve")
        XCTAssertFalse(FileManager.default.fileExists(atPath: link.path))
    }

    func testTrustRevocationIsIdempotentBoundedAndPurged() throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let queue = BridgeQueue(root: root, maximumTotalRecords: 2)
        let storeKeys = BridgeCrypto.generatePrivateKeys()
        let bridgeID = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
        let revocation = try BridgeCrypto.trustRevocation(
            bridgeID: bridgeID,
            registrationDigest: Data(repeating: 7, count: SHA256.byteCount),
            appSigningPrivateKey: storeKeys.signingPrivateKey
        )

        let first = try queue.save(revocation)
        let second = try queue.save(revocation)

        XCTAssertEqual(first, second)
        let persisted = try XCTUnwrap(queue.revocation(for: bridgeID))
        XCTAssertEqual(try persisted.digest(), try revocation.digest())
        XCTAssertEqual(persisted.signature, revocation.signature)
        XCTAssertThrowsError(
            try queue.save(
                BridgeCrypto.trustRevocation(
                    bridgeID: bridgeID,
                    registrationDigest: Data(repeating: 8, count: SHA256.byteCount),
                    appSigningPrivateKey: storeKeys.signingPrivateKey
                )
            )
        ) { error in
            XCTAssertEqual(error as? BridgeProtocolError, .conflictingRecord)
        }

        try queue.purgeAll()
        XCTAssertNil(try queue.revocation(for: bridgeID))
    }

    private func signedRequest(
        keys: BridgePrivateKeys,
        id: UUID = UUID(uuidString: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")!,
        reason: String = "Install the approved credential",
        createdAt: Date = Date()
    ) throws -> SignedBridgeRequest {
        let request = try SecretRequest(
            id: id,
            client: .codex,
            secretID: SecretID(validating: "example-api"),
            targetID: TargetID(validating: "this-mac"),
            consumerID: ConsumerID(validating: "selected-env"),
            reason: reason,
            createdAt: createdAt,
            expiresAt: createdAt.addingTimeInterval(3600)
        )
        return try BridgeCrypto.sign(
            SignedBridgeRequest(
                bridgeID: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!,
                request: request,
                requestNonce: Data(repeating: 9, count: 32)
            ),
            privateKey: keys.signingPrivateKey
        )
    }

    private func temporaryRoot() -> URL {
        FileManager.default.temporaryDirectory.appending(path: "keycourier-bridge-\(UUID().uuidString)")
    }

    private func mode(of url: URL) -> mode_t {
        var info = stat()
        precondition(lstat(url.path, &info) == 0)
        return info.st_mode
    }

    private func agreementPublicKey(from keys: BridgePrivateKeys) throws -> Data {
        try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: keys.keyAgreementPrivateKey).publicKey.rawRepresentation
    }

    private func signingPublicKey(from keys: BridgePrivateKeys) throws -> Data {
        try Curve25519.Signing.PrivateKey(rawRepresentation: keys.signingPrivateKey).publicKey.rawRepresentation
    }
}

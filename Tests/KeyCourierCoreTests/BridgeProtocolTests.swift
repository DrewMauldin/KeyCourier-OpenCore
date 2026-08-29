import CryptoKit
import Foundation
import XCTest
@testable import KeyCourierCore

final class BridgeProtocolTests: XCTestCase {
    func testSigningPayloadIsDeterministicAndDomainSeparated() throws {
        let date = Date(timeIntervalSince1970: 1_700_000_000.1234)
        let secretID = try SecretID(validating: "example-api")
        let targetID = try TargetID(validating: "this-mac")
        let consumerID = try ConsumerID(validating: "selected-env")
        let request = try SecretRequest(
            id: UUID(uuidString: "11111111-1111-1111-1111-111111111111")!,
            client: .codex,
            secretID: secretID,
            targetID: targetID,
            consumerID: consumerID,
            reason: "Install the approved credential",
            createdAt: date,
            expiresAt: date.addingTimeInterval(900)
        )
        let requestDigest = try BridgeCrypto.requestDigest(for: request)
        let sameRequest = try SecretRequest(
            id: request.id,
            client: request.client,
            secretID: secretID,
            targetID: targetID,
            consumerID: consumerID,
            reason: request.reason,
            createdAt: Date(timeIntervalSince1970: date.timeIntervalSince1970 + 0.0001),
            expiresAt: Date(timeIntervalSince1970: request.expiresAt.timeIntervalSince1970 + 0.0001)
        )

        XCTAssertEqual(requestDigest, try BridgeCrypto.requestDigest(for: sameRequest))
        XCTAssertFalse(requestDigest.isEmpty)

        let keys = BridgeCrypto.generatePrivateKeys()
        let registration = try BridgeCrypto.registration(
            bridgeID: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!,
            displayName: "Test bridge",
            keys: keys,
            bridgeNonce: Data(repeating: 1, count: 32),
            createdAt: date,
            expiresAt: date.addingTimeInterval(300)
        )
        XCTAssertNotEqual(requestDigest, try registration.digest())
    }

    func testPairingCodeBindsBothKeysNoncesAndRecordDigests() throws {
        let date = Date(timeIntervalSince1970: 1_700_000_000)
        let bridgeKeys = BridgeCrypto.generatePrivateKeys()
        let appKeys = BridgeCrypto.generatePrivateKeys()
        let registration = try BridgeCrypto.sign(
            BridgeCrypto.registration(
                bridgeID: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!,
                displayName: "Test bridge",
                keys: bridgeKeys,
                bridgeNonce: Data(repeating: 1, count: 32),
                createdAt: date,
                expiresAt: date.addingTimeInterval(300)
            ),
            privateKey: bridgeKeys.signingPrivateKey
        )
        let proposal = try BridgeCrypto.sign(
            BridgeCrypto.pairingProposal(
                for: registration,
                appSigningPrivateKey: appKeys.signingPrivateKey,
                appNonce: Data(repeating: 2, count: 32),
                createdAt: date,
                expiresAt: date.addingTimeInterval(300)
            ),
            privateKey: appKeys.signingPrivateKey
        )

        let expected = try BridgeCrypto.pairingCode(
            registration: registration,
            proposal: proposal,
            at: date.addingTimeInterval(30)
        )
        XCTAssertEqual(expected.count, 14)
        XCTAssertEqual(expected.filter { $0 == "-" }.count, 2)

        let changedProposal = try BridgeCrypto.sign(
            BridgePairingProposal(
                bridgeID: proposal.bridgeID,
                registrationDigest: proposal.registrationDigest,
                appSigningPublicKey: proposal.appSigningPublicKey,
                appNonce: Data(repeating: 3, count: 32),
                createdAt: proposal.createdAt,
                expiresAt: proposal.expiresAt
            ),
            privateKey: appKeys.signingPrivateKey
        )
        XCTAssertNotEqual(
            expected,
            try BridgeCrypto.pairingCode(
                registration: registration,
                proposal: changedProposal,
                at: date.addingTimeInterval(30)
            )
        )
        XCTAssertThrowsError(
            try BridgeCrypto.pairingCode(
                registration: registration,
                proposal: proposal,
                at: date.addingTimeInterval(301)
            )
        ) { error in
            XCTAssertEqual(error as? BridgeProtocolError, .expired)
        }
        XCTAssertNoThrow(try BridgeCrypto.verify(registration, at: date.addingTimeInterval(30)))
        XCTAssertNoThrow(try BridgeCrypto.verify(proposal, at: date.addingTimeInterval(30)))
    }

    func testTrustRevocationIsSignedAndBoundToBridgeAndRegistration() throws {
        let storeKeys = BridgeCrypto.generatePrivateKeys()
        let bridgeID = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
        let registrationDigest = Data(repeating: 7, count: SHA256.byteCount)
        let revokedAt = Date(timeIntervalSince1970: 1_700_000_000)
        let revocation = try BridgeCrypto.trustRevocation(
            bridgeID: bridgeID,
            registrationDigest: registrationDigest,
            appSigningPrivateKey: storeKeys.signingPrivateKey,
            revokedAt: revokedAt
        )
        let storeSigningPublicKey = try signingPublicKey(from: storeKeys)

        XCTAssertNoThrow(
            try BridgeCrypto.verify(
                revocation,
                signingPublicKey: storeSigningPublicKey,
                expectedBridgeID: bridgeID,
                expectedRegistrationDigest: registrationDigest,
                at: revokedAt.addingTimeInterval(1)
            )
        )
        XCTAssertThrowsError(
            try BridgeCrypto.verify(
                revocation,
                signingPublicKey: storeSigningPublicKey,
                expectedBridgeID: UUID(),
                at: revokedAt.addingTimeInterval(1)
            )
        ) { error in
            XCTAssertEqual(error as? BridgeProtocolError, .invalidRecord)
        }
        XCTAssertThrowsError(
            try BridgeCrypto.verify(
                revocation,
                signingPublicKey: storeSigningPublicKey,
                expectedBridgeID: bridgeID,
                expectedRegistrationDigest: Data(repeating: 8, count: SHA256.byteCount),
                at: revokedAt.addingTimeInterval(1)
            )
        ) { error in
            XCTAssertEqual(error as? BridgeProtocolError, .invalidRecord)
        }
        XCTAssertThrowsError(
            try BridgeCrypto.verify(
                revocation,
                signingPublicKey: try signingPublicKey(from: BridgeCrypto.generatePrivateKeys()),
                expectedBridgeID: bridgeID,
                at: revokedAt.addingTimeInterval(1)
            )
        ) { error in
            XCTAssertEqual(error as? BridgeProtocolError, .invalidSignature)
        }
    }

    func testSignedRequestBindsRequestFieldsAndBridgeIdentity() throws {
        let date = Date(timeIntervalSince1970: 1_700_000_000)
        let bridgeKeys = BridgeCrypto.generatePrivateKeys()
        let bridgeID = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
        let request = try makeRequest(createdAt: date)
        let signed = try BridgeCrypto.sign(
            SignedBridgeRequest(
                bridgeID: bridgeID,
                request: request,
                requestNonce: Data(repeating: 7, count: 32)
            ),
            privateKey: bridgeKeys.signingPrivateKey
        )

        XCTAssertNoThrow(try BridgeCrypto.verify(signed, signingPublicKey: try signingPublicKey(from: bridgeKeys), expectedBridgeID: bridgeID, at: date.addingTimeInterval(30)))

        let tamperedRequest = try SecretRequest(
            id: request.id,
            client: request.client,
            secretID: request.secretID,
            targetID: request.targetID,
            consumerID: request.consumerID,
            reason: "A different untrusted reason",
            createdAt: request.createdAt,
            expiresAt: request.expiresAt
        )
        let tampered = try SignedBridgeRequest(
            bridgeID: signed.bridgeID,
            request: tamperedRequest,
            requestNonce: signed.requestNonce,
            signature: signed.signature
        )
        XCTAssertThrowsError(try BridgeCrypto.verify(tampered, signingPublicKey: try signingPublicKey(from: bridgeKeys), at: date.addingTimeInterval(30)))
        XCTAssertThrowsError(try BridgeCrypto.verify(signed, signingPublicKey: try signingPublicKey(from: BridgeCrypto.generatePrivateKeys()), at: date.addingTimeInterval(30)))
    }

    func testExpiredRequestAndCommandFailClosedBeforeUse() throws {
        let now = Date()
        let bridgeKeys = BridgeCrypto.generatePrivateKeys()
        let appKeys = BridgeCrypto.generatePrivateKeys()
        let request = try SecretRequest(
            id: UUID(uuidString: "55555555-5555-5555-5555-555555555555")!,
            client: .codex,
            secretID: SecretID(validating: "example-api"),
            targetID: TargetID(validating: "this-mac"),
            consumerID: ConsumerID(validating: "selected-env"),
            reason: "Install the approved credential",
            createdAt: now.addingTimeInterval(-900),
            expiresAt: now.addingTimeInterval(-1)
        )
        let signedRequest = try BridgeCrypto.sign(
            SignedBridgeRequest(
                bridgeID: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!,
                request: request,
                requestNonce: Data(repeating: 8, count: 32)
            ),
            privateKey: bridgeKeys.signingPrivateKey
        )
        XCTAssertThrowsError(
            try BridgeCrypto.verify(
                signedRequest,
                signingPublicKey: try signingPublicKey(from: bridgeKeys),
                at: now
            )
        ) { error in
            XCTAssertEqual(error as? BridgeProtocolError, .expired)
        }

        let command = try BridgeCrypto.makeDenyCommand(
            request: request,
            bridgeID: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!,
            appSigningPrivateKey: appKeys.signingPrivateKey,
            createdAt: request.createdAt,
            expiresAt: request.expiresAt
        )
        XCTAssertThrowsError(
            try BridgeCrypto.verify(
                command,
                appSigningPublicKey: try signingPublicKey(from: appKeys),
                at: now
            )
        ) { error in
            XCTAssertEqual(error as? BridgeProtocolError, .expired)
        }
    }

    func testDeliveryAndDenialCommandsAreSignedAndCiphertextOnly() throws {
        let now = Date()
        let request = try makeRequest(createdAt: now)
        let bridgeID = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
        let bridgeKeys = BridgeCrypto.generatePrivateKeys()
        let appKeys = BridgeCrypto.generatePrivateKeys()
        let canary = Data("bridge-test-canary-not-for-persistence".utf8)
        let command = try BridgeCrypto.makeDeliveryCommand(
            request: request,
            bridgeID: bridgeID,
            recipientPublicKey: try agreementPublicKey(from: bridgeKeys),
            secret: canary,
            appSigningPrivateKey: appKeys.signingPrivateKey,
            commandID: UUID(uuidString: "33333333-3333-3333-3333-333333333333")!,
            createdAt: now,
            expiresAt: now.addingTimeInterval(900)
        )

        let encoded = try JSONEncoder().encode(command)
        XCTAssertFalse(String(decoding: encoded, as: UTF8.self).contains(String(decoding: canary, as: UTF8.self)))
        XCTAssertEqual(
            try BridgeCrypto.openDeliveryCommand(
                command,
                recipientPrivateKey: bridgeKeys.keyAgreementPrivateKey,
                appSigningPublicKey: try signingPublicKey(from: appKeys),
                expectedBridgeID: bridgeID,
                expectedRequestDigest: try BridgeCrypto.requestDigest(for: request),
                at: now.addingTimeInterval(30)
            ),
            canary
        )
        let otherBridgeKeys = BridgeCrypto.generatePrivateKeys()
        XCTAssertThrowsError(
            try BridgeCrypto.openDeliveryCommand(
                command,
                recipientPrivateKey: otherBridgeKeys.keyAgreementPrivateKey,
                appSigningPublicKey: try signingPublicKey(from: appKeys),
                expectedBridgeID: bridgeID,
                expectedRequestDigest: try BridgeCrypto.requestDigest(for: request),
                at: now.addingTimeInterval(30)
            )
        )

        let alteredCiphertext = Data(repeating: 0, count: command.ciphertext!.count)
        let tampered = try BridgeDeliveryCommand(
            commandID: command.commandID,
            bridgeID: command.bridgeID,
            requestID: command.requestID,
            requestDigest: command.requestDigest,
            targetID: command.targetID,
            consumerID: command.consumerID,
            action: .deliver,
            ephemeralPublicKey: command.ephemeralPublicKey,
            ciphertext: alteredCiphertext,
            createdAt: command.createdAt,
            expiresAt: command.expiresAt,
            signature: command.signature
        )
        XCTAssertThrowsError(
            try BridgeCrypto.openDeliveryCommand(
                tampered,
                recipientPrivateKey: bridgeKeys.keyAgreementPrivateKey,
                appSigningPublicKey: try signingPublicKey(from: appKeys),
                expectedBridgeID: bridgeID,
                expectedRequestDigest: try BridgeCrypto.requestDigest(for: request),
                at: now.addingTimeInterval(30)
            )
        )

        let deny = try BridgeCrypto.makeDenyCommand(
            request: request,
            bridgeID: bridgeID,
            appSigningPrivateKey: appKeys.signingPrivateKey,
            commandID: UUID(uuidString: "44444444-4444-4444-4444-444444444444")!,
            createdAt: now,
            expiresAt: now.addingTimeInterval(900)
        )
        XCTAssertEqual(deny.action, .deny)
        XCTAssertNil(deny.ciphertext)
        XCTAssertNoThrow(try BridgeCrypto.verify(deny, appSigningPublicKey: try signingPublicKey(from: appKeys), at: now.addingTimeInterval(30)))
        XCTAssertThrowsError(
            try BridgeDeliveryCommand(
                commandID: deny.commandID,
                bridgeID: deny.bridgeID,
                requestID: deny.requestID,
                requestDigest: deny.requestDigest,
                targetID: deny.targetID,
                consumerID: deny.consumerID,
                action: .deny,
                ciphertext: Data([1]),
                createdAt: deny.createdAt,
                expiresAt: deny.expiresAt
            )
        )

        let lateExpiry = request.expiresAt.addingTimeInterval(1)
        XCTAssertThrowsError(
            try BridgeCrypto.makeDeliveryCommand(
                request: request,
                bridgeID: bridgeID,
                recipientPublicKey: try agreementPublicKey(from: bridgeKeys),
                secret: canary,
                appSigningPrivateKey: appKeys.signingPrivateKey,
                createdAt: now,
                expiresAt: lateExpiry
            )
        ) { error in
            XCTAssertEqual(error as? BridgeProtocolError, .invalidRecord)
        }
        XCTAssertThrowsError(
            try BridgeCrypto.makeDenyCommand(
                request: request,
                bridgeID: bridgeID,
                appSigningPrivateKey: appKeys.signingPrivateKey,
                createdAt: now,
                expiresAt: lateExpiry
            )
        ) { error in
            XCTAssertEqual(error as? BridgeProtocolError, .invalidRecord)
        }
    }

    func testSignedReceiptBindsContentFreeOutcome() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let request = try makeRequest(createdAt: now)
        let bridgeKeys = BridgeCrypto.generatePrivateKeys()
        let bridgeID = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
        let commandID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
        let receipt = RequestReceipt(
            requestID: request.id,
            status: .verified,
            targetID: request.targetID,
            consumerID: request.consumerID,
            code: .consumerVerified,
            recordedAt: now
        )
        let signed = try BridgeCrypto.sign(
            SignedBridgeReceipt(
                bridgeID: bridgeID,
                commandID: commandID,
                requestDigest: try BridgeCrypto.requestDigest(for: request),
                receipt: receipt
            ),
            privateKey: bridgeKeys.signingPrivateKey
        )

        XCTAssertNoThrow(
            try BridgeCrypto.verify(
                signed,
                signingPublicKey: try signingPublicKey(from: bridgeKeys),
                expectedBridgeID: bridgeID,
                expectedCommandID: commandID,
                expectedRequestID: request.id,
                expectedRequestDigest: try BridgeCrypto.requestDigest(for: request)
            )
        )
        XCTAssertThrowsError(
            try BridgeCrypto.verify(
                signed,
                signingPublicKey: try signingPublicKey(from: bridgeKeys),
                expectedRequestID: UUID(uuidString: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")!
            )
        ) { error in
            XCTAssertEqual(error as? BridgeProtocolError, .invalidRecord)
        }
        let zeroReceipt = RequestReceipt(
            requestID: UUID(uuidString: "00000000-0000-0000-0000-000000000000")!,
            status: .verified,
            targetID: request.targetID,
            consumerID: request.consumerID,
            code: .consumerVerified,
            recordedAt: now
        )
        XCTAssertThrowsError(
            try SignedBridgeReceipt(
                bridgeID: bridgeID,
                commandID: commandID,
                requestDigest: try BridgeCrypto.requestDigest(for: request),
                receipt: zeroReceipt
            )
        ) { error in
            XCTAssertEqual(error as? BridgeProtocolError, .invalidRecord)
        }
        let text = String(decoding: try JSONEncoder().encode(signed), as: UTF8.self).lowercased()
        XCTAssertFalse(text.contains("canary"))
        XCTAssertFalse(text.contains("value"))
        XCTAssertFalse(text.contains("password"))
    }

    func testOutOfRangeSigningDateIsRejectedWithoutTrapping() {
        XCTAssertThrowsError(
            try BridgeTrustGrant(
                bridgeID: UUID(),
                registrationDigest: Data(repeating: 1, count: SHA256.byteCount),
                proposalDigest: Data(repeating: 2, count: SHA256.byteCount),
                grantedAt: Date(timeIntervalSince1970: 1e20)
            )
        ) { error in
            XCTAssertEqual(error as? BridgeProtocolError, .invalidRecord)
        }
    }

    private func makeRequest(createdAt: Date) throws -> SecretRequest {
        try SecretRequest(
            id: UUID(uuidString: "11111111-1111-1111-1111-111111111111")!,
            client: .codex,
            secretID: SecretID(validating: "example-api"),
            targetID: TargetID(validating: "this-mac"),
            consumerID: ConsumerID(validating: "selected-env"),
            reason: "Install the approved credential",
            createdAt: createdAt,
            expiresAt: createdAt.addingTimeInterval(900)
        )
    }

    private func signingPublicKey(from keys: BridgePrivateKeys) throws -> Data {
        try Curve25519.Signing.PrivateKey(rawRepresentation: keys.signingPrivateKey).publicKey.rawRepresentation
    }

    private func agreementPublicKey(from keys: BridgePrivateKeys) throws -> Data {
        try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: keys.keyAgreementPrivateKey).publicKey.rawRepresentation
    }
}

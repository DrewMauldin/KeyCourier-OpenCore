import XCTest
@testable import KeyCourierCore

final class CompanionProtocolTests: XCTestCase {
    func testRequestSummarySignatureBindsEveryDisplayedField() throws {
        let macKeys = CompanionCrypto.generatePrivateKeys()
        let macRegistration = try CompanionCrypto.registration(
            deviceID: UUID(),
            deviceName: "Owner's Mac",
            keys: macKeys
        )
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let summary = try CompanionRequestSummary(
            requestID: UUID(),
            clientName: "Codex",
            credentialName: "Example API",
            destinationName: "This Mac",
            reason: "Configure the approved example consumer",
            createdAt: now,
            expiresAt: now.addingTimeInterval(300)
        )
        let signed = try CompanionCrypto.sign(summary, keys: macKeys)

        XCTAssertNoThrow(
            try CompanionCrypto.verify(
                signed,
                signingPublicKey: macRegistration.signingPublicKey,
                at: now.addingTimeInterval(30)
            )
        )

        let tampered = try CompanionRequestSummary(
            requestID: signed.requestID,
            clientName: signed.clientName,
            credentialName: signed.credentialName,
            destinationName: "VPS",
            reason: signed.reason,
            createdAt: signed.createdAt,
            expiresAt: signed.expiresAt,
            signature: signed.signature
        )
        XCTAssertThrowsError(
            try CompanionCrypto.verify(
                tampered,
                signingPublicKey: macRegistration.signingPublicKey,
                at: now.addingTimeInterval(30)
            )
        )
    }

    func testCloudStoreWithoutEntitlementFailsClosed() async {
        let store = CloudKitCompanionStore()

        do {
            try await store.requireAvailableAccount()
            XCTFail("An unentitled process must not access the CloudKit container")
        } catch {
            XCTAssertEqual(error as? CompanionProtocolError, .cloudUnavailable)
        }
    }

    func testCloudStoreWithoutEntitlementCannotReadAccountIdentifier() async {
        let store = CloudKitCompanionStore()

        do {
            _ = try await store.accountIdentifier()
            XCTFail("An unentitled process must not read a CloudKit account identity")
        } catch {
            XCTAssertEqual(error as? CompanionProtocolError, .cloudUnavailable)
        }
    }

    func testSignedDecisionVerifiesAndTamperingFails() throws {
        let keys = CompanionCrypto.generatePrivateKeys()
        let registration = try CompanionCrypto.registration(
            deviceID: UUID(),
            deviceName: "Owner's iPhone",
            keys: keys
        )
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let decision = try CompanionDecision(
            requestID: UUID(),
            requestDigest: Data(repeating: 7, count: 32),
            deviceID: registration.id,
            action: .approve,
            createdAt: now
        )
        let signed = try CompanionCrypto.sign(decision, keys: keys)

        XCTAssertNoThrow(
            try CompanionCrypto.verify(
                signed,
                signingPublicKey: registration.signingPublicKey,
                at: now.addingTimeInterval(30)
            )
        )

        let tampered = try CompanionDecision(
            id: signed.id,
            requestID: signed.requestID,
            requestDigest: signed.requestDigest,
            deviceID: signed.deviceID,
            action: .deny,
            createdAt: signed.createdAt,
            expiresAt: signed.expiresAt,
            signature: signed.signature
        )
        XCTAssertThrowsError(
            try CompanionCrypto.verify(
                tampered,
                signingPublicKey: registration.signingPublicKey,
                at: now.addingTimeInterval(30)
            )
        )
    }

    func testExpiredDecisionFailsClosed() throws {
        let keys = CompanionCrypto.generatePrivateKeys()
        let registration = try CompanionCrypto.registration(
            deviceID: UUID(),
            deviceName: "Owner's iPhone",
            keys: keys
        )
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let decision = try CompanionCrypto.sign(
            CompanionDecision(
                requestID: UUID(),
                requestDigest: Data(repeating: 9, count: 32),
                deviceID: registration.id,
                action: .approve,
                createdAt: now,
                expiresAt: now.addingTimeInterval(60)
            ),
            keys: keys
        )

        XCTAssertThrowsError(
            try CompanionCrypto.verify(
                decision,
                signingPublicKey: registration.signingPublicKey,
                at: now.addingTimeInterval(61)
            )
        )
    }

    func testSecretEnvelopeRoundTripsWithoutPlaintextInEnvelope() throws {
        let phoneKeys = CompanionCrypto.generatePrivateKeys()
        let macKeys = CompanionCrypto.generatePrivateKeys()
        let phoneRegistration = try CompanionCrypto.registration(
            deviceID: UUID(),
            deviceName: "Owner's iPhone",
            keys: phoneKeys
        )
        let macRegistration = try CompanionCrypto.registration(
            deviceID: UUID(),
            deviceName: "Owner's Mac",
            keys: macKeys
        )
        let plaintext = Data("dummy-not-a-real-secret".utf8)
        let payload = try CompanionSecretPayload(
            secretID: "example-api",
            displayName: "Example API",
            kind: "apiKey",
            value: plaintext,
            projectName: "Canary"
        )
        let now = Date(timeIntervalSince1970: 1_800_000_000)

        let envelope = try CompanionCrypto.seal(
            payload,
            deviceID: phoneRegistration.id,
            recipientPublicKey: macRegistration.keyAgreementPublicKey,
            signingKeys: phoneKeys,
            createdAt: now
        )

        XCTAssertFalse(envelope.ciphertext.range(of: plaintext) != nil)
        let encodedEnvelope = try JSONEncoder().encode(envelope)
        XCTAssertNil(String(data: encodedEnvelope, encoding: .utf8)?.range(of: "example-api"))
        XCTAssertNil(String(data: encodedEnvelope, encoding: .utf8)?.range(of: "Example API"))
        XCTAssertNil(String(data: encodedEnvelope, encoding: .utf8)?.range(of: "Canary"))
        let opened = try CompanionCrypto.open(
            envelope,
            recipientKeys: macKeys,
            senderSigningPublicKey: phoneRegistration.signingPublicKey,
            at: now.addingTimeInterval(30)
        )
        XCTAssertEqual(opened, payload)
    }

    func testUsernamePasswordPayloadRoundTripsAndUsesCompactJSONDeliveryData() throws {
        let phoneKeys = CompanionCrypto.generatePrivateKeys()
        let macKeys = CompanionCrypto.generatePrivateKeys()
        let phoneRegistration = try CompanionCrypto.registration(
            deviceID: UUID(),
            deviceName: "Owner's iPhone",
            keys: phoneKeys
        )
        let macRegistration = try CompanionCrypto.registration(
            deviceID: UUID(),
            deviceName: "Owner's Mac",
            keys: macKeys
        )
        let username = "dummy-user@example.test"
        let password = Data("dummy pass\nwith punctuation".utf8)
        let payload = try CompanionSecretPayload(
            secretID: "example-login",
            displayName: "Example login",
            kind: "password",
            username: username,
            password: password
        )
        let now = Date(timeIntervalSince1970: 1_800_000_000)

        let envelope = try CompanionCrypto.seal(
            payload,
            deviceID: phoneRegistration.id,
            recipientPublicKey: macRegistration.keyAgreementPublicKey,
            signingKeys: phoneKeys,
            createdAt: now
        )
        let encodedEnvelope = try JSONEncoder().encode(envelope)
        let envelopeText = try XCTUnwrap(String(data: encodedEnvelope, encoding: .utf8))

        XCTAssertFalse(envelopeText.contains(username))
        XCTAssertFalse(envelopeText.contains(String(decoding: password, as: UTF8.self)))
        XCTAssertFalse(envelopeText.contains("example-login"))
        XCTAssertFalse(envelopeText.contains("Example login"))

        let opened = try CompanionCrypto.open(
            envelope,
            recipientKeys: macKeys,
            senderSigningPublicKey: phoneRegistration.signingPublicKey,
            at: now.addingTimeInterval(30)
        )
        XCTAssertEqual(opened, payload)
        XCTAssertEqual(opened.username, username)
        XCTAssertEqual(opened.password, password)

        let deliveryData = try opened.deliveryData()
        XCTAssertFalse(deliveryData.contains(0x0A))
        let delivery = try XCTUnwrap(
            JSONSerialization.jsonObject(with: deliveryData) as? [String: String]
        )
        XCTAssertEqual(delivery["username"], username)
        XCTAssertEqual(delivery["password"], String(decoding: password, as: UTF8.self))
    }

    func testReplacementIntentSurvivesEncryptedRoundTrip() throws {
        let phoneKeys = CompanionCrypto.generatePrivateKeys()
        let macKeys = CompanionCrypto.generatePrivateKeys()
        let phoneRegistration = try CompanionCrypto.registration(
            deviceID: UUID(),
            deviceName: "Owner's iPhone",
            keys: phoneKeys
        )
        let macRegistration = try CompanionCrypto.registration(
            deviceID: UUID(),
            deviceName: "Owner's Mac",
            keys: macKeys
        )
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let payload = try CompanionSecretPayload(
            secretID: "example-api",
            displayName: "Example API",
            kind: "apiKey",
            value: Data("replacement-dummy-value".utf8),
            replacesExisting: true
        )

        let envelope = try CompanionCrypto.seal(
            payload,
            deviceID: phoneRegistration.id,
            recipientPublicKey: macRegistration.keyAgreementPublicKey,
            signingKeys: phoneKeys,
            createdAt: now
        )
        let opened = try CompanionCrypto.open(
            envelope,
            recipientKeys: macKeys,
            senderSigningPublicKey: phoneRegistration.signingPublicKey,
            at: now.addingTimeInterval(30)
        )

        XCTAssertTrue(opened.replacesExisting)
        XCTAssertEqual(try opened.deliveryData(), Data("replacement-dummy-value".utf8))
    }

    func testCredentialSummaryPreservesMaterialKind() throws {
        let summary = try CompanionCredentialSummary(
            secretID: "example-login",
            displayName: "Example login",
            kind: "password",
            materialKind: .usernamePassword
        )

        let encoded = try JSONEncoder().encode(summary)
        let decoded = try JSONDecoder().decode(CompanionCredentialSummary.self, from: encoded)

        XCTAssertEqual(decoded, summary)
        XCTAssertEqual(decoded.materialKind, .usernamePassword)
    }

    func testCredentialSummaryDefaultsLegacyRecordsToSingleMaterialKind() throws {
        let legacyRecord = Data(
            #"{"secretID":"legacy-api","displayName":"Legacy API","kind":"apiKey"}"#.utf8
        )

        let summary = try JSONDecoder().decode(CompanionCredentialSummary.self, from: legacyRecord)

        XCTAssertEqual(summary.materialKind, .single)
    }

    func testCredentialMaterialValidationRejectsInvalidExistingMaterial() throws {
        XCTAssertThrowsError(
            try CompanionCredentialMaterial.single(Data()).validated()
        )
        XCTAssertThrowsError(
            try CompanionCredentialMaterial.usernamePassword(
                username: "",
                password: Data("dummy-password".utf8)
            ).validated()
        )
        XCTAssertThrowsError(
            try CompanionCredentialMaterial.usernamePassword(
                username: "dummy-user",
                password: Data([0xFF])
            ).validated()
        )
    }

    func testPayloadRejectsAmbiguousCredentialMaterial() throws {
        let json = Data(
            """
            {"secretID":"example-login","displayName":"Example login","kind":"password","value":"dmFsdWU=","username":"dummy-user","password":"cGFzcw=="}
            """.utf8
        )

        XCTAssertThrowsError(
            try JSONDecoder().decode(CompanionSecretPayload.self, from: json)
        )
    }

    func testSecretEnvelopeCannotBeOpenedByAnotherMac() throws {
        let phoneKeys = CompanionCrypto.generatePrivateKeys()
        let macKeys = CompanionCrypto.generatePrivateKeys()
        let otherMacKeys = CompanionCrypto.generatePrivateKeys()
        let phoneRegistration = try CompanionCrypto.registration(
            deviceID: UUID(),
            deviceName: "Owner's iPhone",
            keys: phoneKeys
        )
        let macRegistration = try CompanionCrypto.registration(
            deviceID: UUID(),
            deviceName: "Owner's Mac",
            keys: macKeys
        )
        let payload = try CompanionSecretPayload(
            secretID: "example-password",
            displayName: "Example password",
            kind: "password",
            value: Data("dummy-not-a-real-secret".utf8)
        )

        let envelope = try CompanionCrypto.seal(
            payload,
            deviceID: phoneRegistration.id,
            recipientPublicKey: macRegistration.keyAgreementPublicKey,
            signingKeys: phoneKeys
        )

        XCTAssertThrowsError(
            try CompanionCrypto.open(
                envelope,
                recipientKeys: otherMacKeys,
                senderSigningPublicKey: phoneRegistration.signingPublicKey
            )
        )
    }

    func testPairingCodeMatchesOnlyTheApprovedMacKey() throws {
        let phoneKeys = CompanionCrypto.generatePrivateKeys()
        let macKeys = CompanionCrypto.generatePrivateKeys()
        let otherMacKeys = CompanionCrypto.generatePrivateKeys()
        var registration = try CompanionCrypto.registration(
            deviceID: UUID(),
            deviceName: "Owner's iPhone",
            keys: phoneKeys
        )
        let mac = try CompanionCrypto.registration(
            deviceID: UUID(),
            deviceName: "Owner's Mac",
            keys: macKeys
        )
        registration.macKeyAgreementPublicKey = mac.keyAgreementPublicKey
        registration.macSigningPublicKey = mac.signingPublicKey
        let expected = try CompanionCrypto.pairingCode(for: registration)

        let otherMac = try CompanionCrypto.registration(
            deviceID: UUID(),
            deviceName: "Another Mac",
            keys: otherMacKeys
        )
        registration.macKeyAgreementPublicKey = otherMac.keyAgreementPublicKey
        registration.macSigningPublicKey = otherMac.signingPublicKey

        XCTAssertNotEqual(expected, try CompanionCrypto.pairingCode(for: registration))
        XCTAssertEqual(expected.count, 14)
    }
}

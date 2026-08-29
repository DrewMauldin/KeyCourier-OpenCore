import XCTest
@testable import KeyCourierCore

final class RequestContractTests: XCTestCase {
    func testSecretIDRejectsWhitespaceAndPathCharacters() throws {
        XCTAssertThrowsError(try SecretID(validating: "contains space"))
        XCTAssertThrowsError(try SecretID(validating: "../../escape"))
    }

    func testValidRequestRoundTripsWithoutSecretMaterial() throws {
        let request = try SecretRequest(
            client: .codex,
            secretID: SecretID(validating: "example-api"),
            targetID: TargetID(validating: "this-mac"),
            consumerID: ConsumerID(validating: "local-example"),
            reason: "Configure the approved example consumer",
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            expiresAt: Date(timeIntervalSince1970: 1_700_000_900)
        )

        let data = try JSONEncoder().encode(request)
        let encoded = try XCTUnwrap(String(data: data, encoding: .utf8))

        XCTAssertFalse(encoded.localizedCaseInsensitiveContains("value"))
        XCTAssertFalse(encoded.localizedCaseInsensitiveContains("password"))
        XCTAssertFalse(encoded.localizedCaseInsensitiveContains("token"))
        XCTAssertEqual(try JSONDecoder().decode(SecretRequest.self, from: data), request)
    }

    func testExpiredRequestFailsValidation() throws {
        let request = try SecretRequest(
            client: .claude,
            secretID: SecretID(validating: "example-api"),
            targetID: TargetID(validating: "this-mac"),
            consumerID: ConsumerID(validating: "local-example"),
            reason: "Configure the approved example consumer",
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            expiresAt: Date(timeIntervalSince1970: 1_700_000_900)
        )

        XCTAssertThrowsError(try request.validate(at: Date(timeIntervalSince1970: 1_700_001_000)))
    }

    func testFarFutureRequestFailsValidation() throws {
        let now = Date()
        let request = try SecretRequest(
            client: .codex,
            secretID: SecretID(validating: "example-api"),
            targetID: TargetID(validating: "this-mac"),
            consumerID: ConsumerID(validating: "local-example"),
            reason: "Configure the approved example consumer",
            createdAt: now.addingTimeInterval(60 * 60)
        )

        XCTAssertThrowsError(try request.validate(at: now))
    }

    func testReceiptEncodingContainsNoSecretBearingField() throws {
        let receipt = RequestReceipt(
            requestID: UUID(),
            status: .verified,
            targetID: try TargetID(validating: "this-mac"),
            consumerID: try ConsumerID(validating: "local-example"),
            code: .consumerVerified,
            recordedAt: Date(timeIntervalSince1970: 1_700_000_000)
        )

        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(receipt)) as? [String: Any])
        let forbidden = Set(["secret", "value", "password", "token", "credential"])

        XCTAssertTrue(forbidden.isDisjoint(with: Set(object.keys.map { $0.lowercased() })))
    }
}

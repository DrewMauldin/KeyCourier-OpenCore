import XCTest
@testable import KeyCourierCore

final class TelegramApprovalTests: XCTestCase {
    func testApprovalIsBoundToPairedChatAndUserAndCanBeConsumedOnce() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = FileTelegramApprovalStore(root: root)
        let configuration = try TelegramConfiguration(
            chatID: 101,
            userID: 202,
            botUsername: "keycourier_test_bot",
            lastUpdateID: 0
        )
        try store.saveConfiguration(configuration)
        let request = try SecretRequest(
            client: .codex,
            secretID: SecretID(validating: "dummy-secret"),
            targetID: TargetID(validating: "this-mac"),
            consumerID: ConsumerID(validating: "this-mac"),
            reason: "Dummy test"
        )
        let record = try store.preparedApproval(for: request)
        try store.markSent(requestID: request.id)

        XCTAssertThrowsError(try store.consume(
            nonce: record.nonce,
            action: .approve,
            chatID: 101,
            userID: 999
        ))
        let consumed = try store.consume(
            nonce: record.nonce,
            action: .approve,
            chatID: 101,
            userID: 202
        )
        XCTAssertEqual(consumed.0, request.id)
        XCTAssertEqual(consumed.1, .approve)
        XCTAssertThrowsError(try store.consume(
            nonce: record.nonce,
            action: .approve,
            chatID: 101,
            userID: 202
        ))
    }

    func testTelegramStateContainsNoRequestIdentifiersOrValuesBeyondOpaqueRequestID() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = FileTelegramApprovalStore(root: root)
        try store.saveConfiguration(try TelegramConfiguration(
            chatID: 101,
            userID: 202,
            botUsername: "keycourier_test_bot",
            lastUpdateID: 0
        ))
        let request = try SecretRequest(
            client: .codex,
            secretID: SecretID(validating: "dummy-secret"),
            targetID: TargetID(validating: "this-mac"),
            consumerID: ConsumerID(validating: "this-mac"),
            reason: "A reason that must not be persisted"
        )
        _ = try store.preparedApproval(for: request)

        let data = try Data(contentsOf: root.appending(path: "telegram.json"))
        let text = try XCTUnwrap(String(data: data, encoding: .utf8))
        XCTAssertFalse(text.contains("dummy-secret"))
        XCTAssertFalse(text.contains("A reason"))
        XCTAssertFalse(text.contains("this-mac"))
    }

    func testExpiredApprovalFailsClosed() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = FileTelegramApprovalStore(root: root)
        try store.save(TelegramApprovalState(
            configuration: try TelegramConfiguration(
                chatID: 101,
                userID: 202,
                botUsername: "keycourier_test_bot",
                lastUpdateID: 0
            ),
            approvals: [try TelegramApprovalRecord(
                requestID: UUID(),
                nonce: "0123456789abcdef0123456789abcdef",
                expiresAt: Date().addingTimeInterval(-1),
                state: .sent,
                sendAttempts: 1
            )]
        ))

        XCTAssertThrowsError(try store.consume(
            nonce: "0123456789abcdef0123456789abcdef",
            action: .approve,
            chatID: 101,
            userID: 202
        ))
    }

    func testBotTokenValidationRejectsPathCharacters() {
        let valid = "123456:" + String(repeating: "a", count: 24)
        XCTAssertNoThrow(try TelegramBotTokenStore.validatedToken(valid))
        XCTAssertThrowsError(try TelegramBotTokenStore.validatedToken("123456:../../not-allowed-token"))
    }
}

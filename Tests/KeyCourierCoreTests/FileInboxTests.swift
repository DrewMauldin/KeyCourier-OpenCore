import Darwin
import XCTest
@testable import KeyCourierCore

final class FileInboxTests: XCTestCase {
    func testRequestFilesUseRestrictivePermissions() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let inbox = FileRequestInbox(root: root)
        let request = try SecretRequest(
            client: .opencode,
            secretID: SecretID(validating: "example-api"),
            targetID: TargetID(validating: "this-mac"),
            consumerID: ConsumerID(validating: "local-example"),
            reason: "Configure the approved example consumer"
        )

        let file = try inbox.submit(request)
        let directoryMode = try mode(of: root)
        let fileMode = try mode(of: file)

        XCTAssertEqual(directoryMode & 0o777, 0o700)
        XCTAssertEqual(fileMode & 0o777, 0o600)
        XCTAssertEqual(try inbox.pending(at: request.createdAt).map(\.id), [request.id])
    }

    func testSubmitRejectsWhenPendingRequestLimitReached() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let inbox = FileRequestInbox(root: root)
        let createdAt = Date()

        for _ in 0..<100 {
            let request = try SecretRequest(
                client: .opencode,
                secretID: SecretID(validating: "example-api"),
                targetID: TargetID(validating: "this-mac"),
                consumerID: ConsumerID(validating: "local-example"),
                reason: "Configure the approved example consumer",
                createdAt: createdAt,
                expiresAt: createdAt.addingTimeInterval(3600)
            )
            try inbox.submit(request)
        }

        let overflow = try SecretRequest(
            client: .opencode,
            secretID: SecretID(validating: "example-api"),
            targetID: TargetID(validating: "this-mac"),
            consumerID: ConsumerID(validating: "local-example"),
            reason: "Configure the approved example consumer",
            createdAt: createdAt,
            expiresAt: createdAt.addingTimeInterval(3600)
        )

        XCTAssertThrowsError(try inbox.submit(overflow))
    }

    private func mode(of url: URL) throws -> mode_t {
        var info = stat()
        guard lstat(url.path, &info) == 0 else {
            throw POSIXError(.ENOENT)
        }
        return info.st_mode
    }
}

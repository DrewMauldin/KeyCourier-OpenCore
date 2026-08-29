import XCTest
@testable import KeyCourierCore

final class AgentCommandTests: XCTestCase {
    func testRequestCommandBuildsContentFreeRequest() throws {
        let command = try AgentCommand.parse(arguments: [
            "request",
            "--client", "codex",
            "--secret-id", "example-api",
            "--target", "this-mac",
            "--consumer", "local-example",
            "--reason", "Configure the approved example consumer"
        ])

        guard case .request(let request) = command else {
            return XCTFail("Expected request command")
        }
        XCTAssertEqual(request.client, .codex)
        XCTAssertEqual(request.secretID.rawValue, "example-api")
        XCTAssertEqual(request.consumerID.rawValue, "local-example")
    }

    func testRequestCommandRejectsSecretBearingFlags() {
        XCTAssertThrowsError(try AgentCommand.parse(arguments: [
            "request",
            "--client", "codex",
            "--secret-id", "example-api",
            "--target", "this-mac",
            "--consumer", "local-example",
            "--reason", "Configure consumer",
            "--value", "dummy-not-a-real-secret"
        ]))
    }

    func testDestinationShortcutBuildsTheMacMiniRequest() throws {
        let command = try AgentCommand.parse(arguments: [
            "request",
            "--client", "codex",
            "--destination", "mac-mini",
            "--reason", "Install the saved credential"
        ])

        guard case .request(let request) = command else {
            return XCTFail("Expected request command")
        }
        XCTAssertEqual(request.secretID.rawValue, "mac-mini-secret")
        XCTAssertEqual(request.consumerID.rawValue, "mac-mini")
        XCTAssertEqual(request.targetID.rawValue, "mac-mini")
    }

    func testDestinationShortcutBuildsTheThisMacRequest() throws {
        let command = try AgentCommand.parse(arguments: [
            "request",
            "--client", "codex",
            "--destination", "this-mac",
            "--reason", "Install the saved credential locally"
        ])

        guard case .request(let request) = command else {
            return XCTFail("Expected request command")
        }
        XCTAssertEqual(request.secretID.rawValue, "this-mac-secret")
        XCTAssertEqual(request.consumerID.rawValue, "this-mac")
        XCTAssertEqual(request.targetID.rawValue, "this-mac")
    }

    func testDestinationShortcutBuildsProjectionExecutorRequest() throws {
        let command = try AgentCommand.parse(arguments: [
            "request",
            "--client", "codex",
            "--destination", "cloud-memory-projection",
            "--reason", "Configure the approved projection executor"
        ])

        guard case .request(let request) = command else {
            return XCTFail("Expected request command")
        }
        XCTAssertEqual(request.secretID.rawValue, "cloud-memory-projection-secret")
        XCTAssertEqual(request.consumerID.rawValue, "cloud-memory-projection")
        XCTAssertEqual(request.targetID.rawValue, "vps")
    }

    func testDestinationShortcutRejectsUnknownAndMixedForms() {
        XCTAssertThrowsError(try AgentCommand.parse(arguments: [
            "request",
            "--client", "claude",
            "--destination", "unknown-host",
            "--reason", "Install the saved credential"
        ]))
        XCTAssertThrowsError(try AgentCommand.parse(arguments: [
            "request",
            "--client", "claude",
            "--destination", "vps",
            "--secret-id", "vps-secret",
            "--target", "vps",
            "--consumer", "vps",
            "--reason", "Install the saved credential"
        ]))
    }

    func testStatusCommandRequiresUUID() throws {
        let id = UUID()
        XCTAssertEqual(
            try AgentCommand.parse(arguments: ["status", id.uuidString]),
            .status(id)
        )
        XCTAssertThrowsError(try AgentCommand.parse(arguments: ["status", "not-a-uuid"]))
    }

    func testIdentifierOnlyAndDoctorCommandsTakeNoOptions() throws {
        XCTAssertEqual(try AgentCommand.parse(arguments: ["secrets"]), .secrets)
        XCTAssertEqual(try AgentCommand.parse(arguments: ["consumers"]), .consumers)
        XCTAssertEqual(try AgentCommand.parse(arguments: ["doctor"]), .doctor)

        XCTAssertThrowsError(try AgentCommand.parse(arguments: ["secrets", "--values"]))
        XCTAssertThrowsError(try AgentCommand.parse(arguments: ["consumers", "--verbose"]))
        XCTAssertThrowsError(try AgentCommand.parse(arguments: ["doctor", "--repair"]))
    }
}

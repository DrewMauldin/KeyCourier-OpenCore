import Darwin
import XCTest
@testable import KeyCourierCore

final class DotenvInstallerTests: XCTestCase {
    func testInstallReplacesOnlyAllowlistedVariableAndCreatesProtectedBackup() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let destination = root.appending(path: "consumer.env")
        try Data("UNCHANGED=present\nEXAMPLE_KEY=old-placeholder\n".utf8).write(to: destination)
        let profile = try ConsumerProfile(
            id: ConsumerID(validating: "local-example"),
            displayName: "Local example",
            targetID: TargetID(validating: "this-mac"),
            destination: .dotenv(path: destination.path, variable: "EXAMPLE_KEY")
        )

        let result = try DotenvInstaller().install(Data("dummy-not-a-real-secret".utf8), for: profile)
        let installed = try String(contentsOf: destination, encoding: .utf8)
        let backup = URL(filePath: result.backupPath!)

        XCTAssertEqual(installed, "UNCHANGED=present\nEXAMPLE_KEY=\"dummy-not-a-real-secret\"\n")
        XCTAssertEqual(try String(contentsOf: backup, encoding: .utf8), "UNCHANGED=present\nEXAMPLE_KEY=old-placeholder\n")
        XCTAssertEqual(try mode(of: destination) & 0o777, 0o600)
        XCTAssertEqual(try mode(of: backup) & 0o777, 0o600)
    }

    func testInstallRejectsMultilineValues() throws {
        let profile = try ConsumerProfile(
            id: ConsumerID(validating: "local-example"),
            displayName: "Local example",
            targetID: TargetID(validating: "this-mac"),
            destination: .dotenv(path: "/tmp/example.env", variable: "EXAMPLE_KEY")
        )

        XCTAssertThrowsError(try DotenvInstaller().install(Data("line-one\nline-two".utf8), for: profile))
    }

    func testInstallPreservesConsumerDirectoryPermissions() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o755]
        )
        XCTAssertEqual(chmod(root.path, 0o755), 0)
        defer { try? FileManager.default.removeItem(at: root) }
        let destination = root.appending(path: "consumer.env")
        let profile = try ConsumerProfile(
            id: ConsumerID(validating: "local-example"),
            displayName: "Local example",
            targetID: TargetID(validating: "this-mac"),
            destination: .dotenv(path: destination.path, variable: "EXAMPLE_KEY")
        )

        _ = try DotenvInstaller().install(Data("dummy-not-a-real-secret".utf8), for: profile)

        XCTAssertEqual(try mode(of: root) & 0o777, 0o755)
    }

    func testInstallRejectsOversizedValues() throws {
        let profile = try ConsumerProfile(
            id: ConsumerID(validating: "local-example"),
            displayName: "Local example",
            targetID: TargetID(validating: "this-mac"),
            destination: .dotenv(path: "/tmp/example.env", variable: "EXAMPLE_KEY")
        )

        XCTAssertThrowsError(try DotenvInstaller().install(Data(repeating: 65, count: 64 * 1024 + 1), for: profile))
    }

    func testInstallLoginWritesUsernameAndPasswordAsSeparateVariables() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let destination = root.appending(path: "login.env")
        let profile = try ConsumerProfile(
            id: ConsumerID(validating: "local-login"),
            displayName: "Local login",
            targetID: TargetID(validating: "this-mac"),
            destination: .dotenvLogin(
                path: destination.path,
                usernameVariable: "APP_USERNAME",
                passwordVariable: "APP_PASSWORD"
            )
        )
        let encoded = try CompanionCredentialMaterial.usernamePassword(
            username: "owner@example.com",
            password: Data("dummy-password".utf8)
        ).deliveryData()
        let login = try CompanionCredentialMaterial.usernamePassword(fromDeliveryData: encoded)

        _ = try DotenvInstaller().install(
            username: login.username,
            password: login.password,
            for: profile
        )

        XCTAssertEqual(
            try String(contentsOf: destination, encoding: .utf8),
            "APP_USERNAME=\"owner@example.com\"\nAPP_PASSWORD=\"dummy-password\"\n"
        )
    }

    private func mode(of url: URL) throws -> mode_t {
        var info = stat()
        guard lstat(url.path, &info) == 0 else {
            throw POSIXError(.ENOENT)
        }
        return info.st_mode
    }
}

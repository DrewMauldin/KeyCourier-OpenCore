import Darwin
import Foundation
import XCTest
@testable import KeyCourierCore

final class SecureFileSystemTests: XCTestCase {
    func testAtomicWriteCreatesPrivateDirectoriesAndReadableFile() throws {
        let root = try makeRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let destination = root.appending(path: "nested/secret.json")
        try SecureFileSystem.writeAtomically(Data("owner-controlled".utf8), to: destination)

        XCTAssertEqual(
            try SecureFileSystem.readRegularFile(destination, maximumBytes: 1024),
            Data("owner-controlled".utf8)
        )
        XCTAssertEqual(try mode(of: destination.deletingLastPathComponent()) & 0o777, 0o700)
        XCTAssertEqual(try mode(of: destination) & 0o777, 0o600)
    }

    func testEnsurePrivateDirectoryRejectsAncestorSymlink() throws {
        let root = try makeRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let real = root.appending(path: "real")
        let link = root.appending(path: "link")
        try FileManager.default.createDirectory(at: real, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: real)

        let child = link.appending(path: "child")
        XCTAssertThrowsError(try SecureFileSystem.ensurePrivateDirectory(child))
        XCTAssertFalse(FileManager.default.fileExists(atPath: real.appending(path: "child").path))
    }

    func testReadRejectsHardLinkedFile() throws {
        let root = try makeRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let original = root.appending(path: "original")
        let hardlink = root.appending(path: "hardlink")
        try Data("owner-controlled".utf8).write(to: original)
        try FileManager.default.linkItem(at: original, to: hardlink)

        XCTAssertThrowsError(
            try SecureFileSystem.readRegularFile(hardlink, maximumBytes: 1024)
        )
    }

    func testWriteRejectsHardLinkedDestination() throws {
        let root = try makeRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let original = root.appending(path: "original")
        let destination = root.appending(path: "destination")
        try Data("preserve".utf8).write(to: original)
        try FileManager.default.linkItem(at: original, to: destination)

        XCTAssertThrowsError(
            try SecureFileSystem.writeAtomically(
                Data("replacement".utf8),
                to: destination,
                directoryPolicy: .existingOwnerControlled
            )
        )
        XCTAssertEqual(try Data(contentsOf: original), Data("preserve".utf8))
    }

    func testWriteRejectsSymlinkDestination() throws {
        let root = try makeRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let outside = root.appending(path: "outside")
        let destination = root.appending(path: "destination")
        try Data("preserve".utf8).write(to: outside)
        try FileManager.default.createSymbolicLink(at: destination, withDestinationURL: outside)

        XCTAssertThrowsError(
            try SecureFileSystem.writeAtomically(
                Data("replacement".utf8),
                to: destination,
                directoryPolicy: .existingOwnerControlled
            )
        )
        XCTAssertEqual(try Data(contentsOf: outside), Data("preserve".utf8))
    }

    func testReadRejectsFIFOWithoutBlocking() throws {
        let root = try makeRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let fifo = root.appending(path: "untrusted.fifo")
        XCTAssertEqual(mkfifo(fifo.path, 0o600), 0)

        XCTAssertThrowsError(
            try SecureFileSystem.readRegularFile(fifo, maximumBytes: 1024)
        )
    }

    func testExclusiveAtomicWritePreservesExistingDestination() throws {
        let root = try makeRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let destination = root.appending(path: "record.json")
        try SecureFileSystem.writeAtomicallyIfAbsent(Data("first".utf8), to: destination)

        XCTAssertThrowsError(
            try SecureFileSystem.writeAtomicallyIfAbsent(Data("second".utf8), to: destination)
        ) { error in
            XCTAssertEqual(error as? KeyCourierError, .replayedRequest)
        }
        XCTAssertEqual(
            try SecureFileSystem.readRegularFile(destination, maximumBytes: 1024),
            Data("first".utf8)
        )
    }

    func testTrustedAnchorAllowsEqualAndDescendantPathsButRejectsOutside() throws {
        let root = try makeRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let anchor = root.appending(path: "anchor")
        try FileManager.default.createDirectory(at: anchor, withIntermediateDirectories: true)

        try SecureFileSystem.ensurePrivateDirectory(anchor, trustedAnchor: anchor)
        let destination = anchor.appending(path: "nested/secret.json")
        try SecureFileSystem.writeAtomically(
            Data("anchored".utf8),
            to: destination,
            trustedAnchor: anchor
        )
        XCTAssertEqual(
            try SecureFileSystem.readRegularFile(
                destination,
                maximumBytes: 1024,
                trustedAnchor: anchor
            ),
            Data("anchored".utf8)
        )

        let outside = root.appending(path: "outside/secret.json")
        XCTAssertThrowsError(
            try SecureFileSystem.writeAtomically(
                Data("escape".utf8),
                to: outside,
                trustedAnchor: anchor
            )
        ) { error in
            XCTAssertEqual(error as? KeyCourierError, .unsafeFile)
        }
    }

    func testTrustedAnchorRejectsSymlinkInAnchorAncestors() throws {
        let root = try makeRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let realParent = root.appending(path: "real-parent")
        let linkedParent = root.appending(path: "linked-parent")
        let realAnchor = realParent.appending(path: "anchor")
        let linkedAnchor = linkedParent.appending(path: "anchor")
        try FileManager.default.createDirectory(at: realAnchor, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: linkedParent, withDestinationURL: realParent)

        XCTAssertThrowsError(
            try SecureFileSystem.ensurePrivateDirectory(linkedAnchor, trustedAnchor: linkedAnchor)
        )
        XCTAssertTrue((try mode(of: linkedParent) & S_IFMT) == S_IFLNK)
        XCTAssertTrue(FileManager.default.fileExists(atPath: realAnchor.path))
    }

    func testTrustedAnchorRejectsTraversalAndSymlinkComponents() throws {
        let root = try makeRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let anchor = root.appending(path: "anchor")
        let outside = root.appending(path: "outside")
        try FileManager.default.createDirectory(at: anchor, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        let link = anchor.appending(path: "link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: outside)

        let traversal = URL(fileURLWithPath: anchor.path + "/../outside/escape.json")
        XCTAssertThrowsError(
            try SecureFileSystem.writeAtomically(
                Data("escape".utf8),
                to: traversal,
                trustedAnchor: anchor
            )
        ) { error in
            XCTAssertEqual(error as? KeyCourierError, .unsafeFile)
        }

        XCTAssertThrowsError(
            try SecureFileSystem.writeAtomically(
                Data("escape".utf8),
                to: link.appending(path: "escape.json"),
                trustedAnchor: anchor
            )
        )
        XCTAssertFalse(FileManager.default.fileExists(atPath: outside.appending(path: "escape.json").path))
    }

    private func makeRoot() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appending(path: "keycourier-fs-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        XCTAssertEqual(chmod(root.path, 0o700), 0)
        return root
    }

    private func mode(of url: URL) throws -> mode_t {
        var info = stat()
        guard lstat(url.path, &info) == 0 else { throw POSIXError(.ENOENT) }
        return info.st_mode
    }
}

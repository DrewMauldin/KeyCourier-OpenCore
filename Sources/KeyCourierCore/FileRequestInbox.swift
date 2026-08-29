import Foundation

public struct AppDirectories: Sendable {
    public let root: URL

    public var inbox: URL { root.appending(path: "Inbox", directoryHint: .isDirectory) }
    public var receipts: URL { root.appending(path: "Receipts", directoryHint: .isDirectory) }
    public var metadata: URL { root.appending(path: "Metadata", directoryHint: .isDirectory) }
    public var installations: URL { root.appending(path: "Installations", directoryHint: .isDirectory) }

    public init(root: URL) {
        self.root = root
    }

    public static var standard: AppDirectories {
        let root = FileManager.default.homeDirectoryForCurrentUser
            .appending(path: "Library/Application Support/KeyCourier", directoryHint: .isDirectory)
        return AppDirectories(root: root)
    }

    public func prepareInstallations() throws {
        try SecureFileSystem.ensurePrivateDirectory(installations)
    }
}

public struct FileRequestInbox: Sendable {
    private static let maximumRequestBytes = 16 * 1024
    private static let maximumPendingRequests = 100

    public let root: URL

    public init(root: URL) {
        self.root = root
    }

    @discardableResult
    public func submit(_ request: SecretRequest) throws -> URL {
        try request.validate()
        try SecureFileSystem.ensurePrivateDirectory(root)
        let destination = requestURL(for: request.id)
        guard try !SecureFileSystem.fileExists(destination) else {
            return destination
        }
        guard try pending().count < Self.maximumPendingRequests else {
            throw KeyCourierError.requestLimitExceeded
        }

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        try SecureFileSystem.writeAtomically(encoder.encode(request), to: destination)
        return destination
    }

    public func pending(at date: Date = Date()) throws -> [SecretRequest] {
        try SecureFileSystem.ensurePrivateDirectory(root)
        let files = try FileManager.default.contentsOfDirectory(
            at: root,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        )
        .filter { $0.lastPathComponent.hasSuffix(".request.json") }
        .sorted { $0.lastPathComponent < $1.lastPathComponent }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return Array(files.compactMap { file in
            guard let data = try? SecureFileSystem.readRegularFile(file, maximumBytes: Self.maximumRequestBytes),
                  let request = try? decoder.decode(SecretRequest.self, from: data),
                  (try? request.validate(at: date)) != nil else {
                return nil
            }
            return request
        }
        .sorted { $0.createdAt > $1.createdAt }
        .prefix(Self.maximumPendingRequests))
    }

    public func remove(_ requestID: UUID) throws {
        let destination = requestURL(for: requestID)
        guard try SecureFileSystem.fileExists(destination) else { return }
        try FileManager.default.removeItem(at: destination)
    }

    private func requestURL(for id: UUID) -> URL {
        root.appending(path: "\(id.uuidString.lowercased()).request.json")
    }
}

public struct FileReceiptStore: Sendable {
    private static let maximumReceiptBytes = 8 * 1024

    public let root: URL
    private let trustedAnchor: URL?

    public init(root: URL, trustedAnchor: URL? = nil) {
        self.root = root
        self.trustedAnchor = trustedAnchor
    }

    @discardableResult
    public func record(_ receipt: RequestReceipt) throws -> URL {
        try SecureFileSystem.ensurePrivateDirectory(root, trustedAnchor: trustedAnchor)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        let destination = receiptURL(for: receipt.requestID)
        try SecureFileSystem.writeAtomically(
            encoder.encode(receipt),
            to: destination,
            trustedAnchor: trustedAnchor
        )
        return destination
    }

    public func receipt(for requestID: UUID) throws -> RequestReceipt? {
        let destination = receiptURL(for: requestID)
        guard try SecureFileSystem.fileExists(destination, trustedAnchor: trustedAnchor) else { return nil }
        let data = try SecureFileSystem.readRegularFile(
            destination,
            maximumBytes: Self.maximumReceiptBytes,
            trustedAnchor: trustedAnchor
        )
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(RequestReceipt.self, from: data)
    }

    public func all() throws -> [RequestReceipt] {
        try SecureFileSystem.ensurePrivateDirectory(root, trustedAnchor: trustedAnchor)
        return try FileManager.default.contentsOfDirectory(
            at: root,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        )
        .filter { $0.lastPathComponent.hasSuffix(".receipt.json") }
        .compactMap { file -> RequestReceipt? in
            guard let id = UUID(uuidString: file.deletingPathExtension().deletingPathExtension().lastPathComponent) else {
                return nil
            }
            return try? receipt(for: id)
        }
        .sorted { $0.recordedAt > $1.recordedAt }
    }

    private func receiptURL(for id: UUID) -> URL {
        root.appending(path: "\(id.uuidString.lowercased()).receipt.json")
    }
}

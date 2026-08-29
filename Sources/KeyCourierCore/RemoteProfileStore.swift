import Foundation

public struct FileRemoteAgeProfileStore: Sendable {
    private static let maximumBytes = 256 * 1024

    private let root: URL
    private var profilesURL: URL { root.appending(path: "remote-profiles.json") }

    public init(root: URL) {
        self.root = root
    }

    public func profiles() throws -> [RemoteAgeProfile] {
        try SecureFileSystem.ensurePrivateDirectory(root)
        guard try SecureFileSystem.fileExists(profilesURL) else { return [] }
        let data = try SecureFileSystem.readRegularFile(
            profilesURL,
            maximumBytes: Self.maximumBytes
        )
        let profiles = try JSONDecoder().decode([RemoteAgeProfile].self, from: data)
        _ = try RemoteAgeAllowlist(profiles: profiles)
        return profiles
    }

    public func save(_ profiles: [RemoteAgeProfile]) throws {
        _ = try RemoteAgeAllowlist(profiles: profiles)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try SecureFileSystem.ensurePrivateDirectory(root)
        try SecureFileSystem.writeAtomically(encoder.encode(profiles), to: profilesURL)
    }
}

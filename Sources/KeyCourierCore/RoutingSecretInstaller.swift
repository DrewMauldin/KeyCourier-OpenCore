import Foundation

public struct RoutingSecretInstaller: RequestAwareSecretInstaller, Sendable {
    private let local: DotenvSecretInstaller
    private let remote: RemoteAgeSecretInstaller?

    public init(
        local: DotenvSecretInstaller = DotenvSecretInstaller(),
        remote: RemoteAgeSecretInstaller?
    ) {
        self.local = local
        self.remote = remote
    }

    public func install(_ secret: Data, for profile: ConsumerProfile) async throws {
        guard case .dotenv = profile.destination else {
            throw KeyCourierError.unsupportedDestination
        }
        try await local.install(secret, for: profile)
    }

    public func install(
        _ secret: Data,
        for profile: ConsumerProfile,
        request: SecretRequest
    ) async throws {
        switch profile.destination {
        case .dotenv:
            try await local.install(secret, for: profile)
        case .dotenvLogin:
            throw KeyCourierError.unsupportedDestination
        case .remoteAge:
            guard let remote else { throw KeyCourierError.unsupportedDestination }
            try await remote.install(secret, for: profile, request: request)
        }
    }
}

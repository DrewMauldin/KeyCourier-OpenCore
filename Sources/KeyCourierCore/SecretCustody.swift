import Foundation
import LocalAuthentication

public protocol OwnerPresenceAuthorizing: Sendable {
    func authorize(reason: String) async throws
}

public struct LocalOwnerPresenceAuthorizer: OwnerPresenceAuthorizing, Sendable {
    public init() {}

    public func authorize(reason: String) async throws {
        let context = LAContext()
        context.localizedReason = reason
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            throw error ?? KeyCourierError.approvalInvalid
        }
        guard try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) else {
            throw KeyCourierError.approvalInvalid
        }
    }
}

public protocol SecretStore: Sendable {
    func save(_ secret: Data, id: SecretID) async throws
    func read(id: SecretID, reason: String) async throws -> Data?
    func delete(id: SecretID, reason: String) async throws
}

public protocol SecretInstaller: Sendable {
    func install(_ secret: Data, for profile: ConsumerProfile) async throws
}

public protocol RequestAwareSecretInstaller: SecretInstaller {
    func install(_ secret: Data, for profile: ConsumerProfile, request: SecretRequest) async throws
}

public struct DotenvSecretInstaller: SecretInstaller {
    public init() {}

    public func install(_ secret: Data, for profile: ConsumerProfile) async throws {
        _ = try await Task.detached(priority: .userInitiated) {
            try DotenvInstaller().install(secret, for: profile)
        }.value
    }
}

public struct ApprovalCoordinator: Sendable {
    private static let authenticationReason = "Approve KeyCourier secret delivery"

    private let secretStore: any SecretStore
    private let installer: any SecretInstaller

    public init(secretStore: any SecretStore, installer: any SecretInstaller) {
        self.secretStore = secretStore
        self.installer = installer
    }

    public func approve(
        _ request: SecretRequest,
        consumers: [ConsumerProfile],
        secrets: [SecretMetadata],
        at date: Date = Date()
    ) async -> RequestReceipt {
        do {
            try request.validate(at: date)
        } catch {
            return receipt(for: request, status: .failed, code: .validationFailed)
        }

        guard let consumer = consumers.first(where: { $0.id == request.consumerID }) else {
            return receipt(for: request, status: .failed, code: .consumerMissing)
        }
        guard consumer.targetID == request.targetID else {
            return receipt(for: request, status: .failed, code: .validationFailed)
        }
        guard let metadata = secrets.first(where: { $0.secretID == request.secretID }) else {
            return receipt(for: request, status: .failed, code: .secretMissing)
        }
        if let expiresAt = metadata.expiresAt, expiresAt <= date {
            return receipt(for: request, status: .failed, code: .secretExpired)
        }
        do {
            guard let secret = try await secretStore.read(
                id: request.secretID,
                reason: Self.authenticationReason
            ) else {
                return receipt(for: request, status: .failed, code: .secretMissing)
            }
            switch consumer.destination {
            case .dotenv:
                try await installer.install(secret, for: consumer)
            case .dotenvLogin:
                return receipt(for: request, status: .notConfigured, code: .targetUnavailable)
            case .remoteAge:
                guard let installer = installer as? any RequestAwareSecretInstaller else {
                    return receipt(for: request, status: .notConfigured, code: .targetUnavailable)
                }
                try await installer.install(secret, for: consumer, request: request)
            }
            return receipt(for: request, status: .verified, code: .consumerVerified)
        } catch {
            return receipt(for: request, status: .failed, code: .deliveryFailed)
        }
    }

    public func deny(_ request: SecretRequest) -> RequestReceipt {
        receipt(for: request, status: .denied, code: .ownerDenied)
    }

    private func receipt(
        for request: SecretRequest,
        status: ReceiptStatus,
        code: ReceiptCode
    ) -> RequestReceipt {
        RequestReceipt(
            requestID: request.id,
            status: status,
            targetID: request.targetID,
            consumerID: request.consumerID,
            code: code
        )
    }
}

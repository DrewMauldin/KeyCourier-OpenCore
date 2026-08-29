import Foundation
import LocalAuthentication
import Security

public struct KeychainSecretStore: SecretStore {
    private static let userPresenceService = "com.drewsdigest.KeyCourier.secrets"
    private static let approvalGatedService = "com.drewsdigest.KeyCourier.secrets.approval-gated"

    public init() {}

    /// Checks whether either protection variant exists without requesting or
    /// returning the protected value. This is used by the Store app to avoid
    /// overwriting a credential created by the main app when Store metadata is
    /// unavailable to the sandbox.
    public func contains(id: SecretID) async throws -> Bool {
        try await Task.detached(priority: .userInitiated) {
            let authenticationContext = LAContext()
            authenticationContext.interactionNotAllowed = true
            for service in [Self.approvalGatedService, Self.userPresenceService] {
                var query = Self.baseQuery(id: id, service: service)
                query[kSecMatchLimit as String] = kSecMatchLimitOne
                query[kSecReturnAttributes as String] = true
                query[kSecReturnData as String] = false
                query[kSecUseAuthenticationContext as String] = authenticationContext

                var result: CFTypeRef?
                let status = SecItemCopyMatching(query as CFDictionary, &result)
                if status == errSecSuccess {
                    return true
                }
                if status != errSecItemNotFound {
                    throw KeyCourierError.keychainFailure(status)
                }
            }
            return false
        }.value
    }

    public func save(_ secret: Data, id: SecretID) async throws {
        try await save(secret, id: id, allowsTelegramApproval: false)
    }

    public func save(_ secret: Data, id: SecretID, allowsTelegramApproval: Bool) async throws {
        try await save(secret, id: id, allowsRemoteApproval: allowsTelegramApproval)
    }

    public func save(_ secret: Data, id: SecretID, allowsRemoteApproval: Bool) async throws {
        guard !secret.isEmpty, secret.count <= 64 * 1024 else {
            throw KeyCourierError.malformedSecretValue
        }
        try await Task.detached(priority: .userInitiated) {
            let targetService = allowsRemoteApproval ? Self.approvalGatedService : Self.userPresenceService
            let oldService = allowsRemoteApproval ? Self.userPresenceService : Self.approvalGatedService
            var query = Self.baseQuery(id: id, service: targetService)
            let status = SecItemUpdate(
                query as CFDictionary,
                [kSecValueData as String: secret] as CFDictionary
            )
            if status == errSecItemNotFound {
                query[kSecValueData as String] = secret
                if allowsRemoteApproval {
                    query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
                } else {
                    var error: Unmanaged<CFError>?
                    guard let access = SecAccessControlCreateWithFlags(
                        nil,
                        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                        .userPresence,
                        &error
                    ) else {
                        throw KeyCourierError.keychainFailure(errSecParam)
                    }
                    query[kSecAttrAccessControl as String] = access
                }
                let addStatus = SecItemAdd(query as CFDictionary, nil)
                guard addStatus == errSecSuccess else {
                    throw KeyCourierError.keychainFailure(addStatus)
                }
            } else if status != errSecSuccess {
                throw KeyCourierError.keychainFailure(status)
            }

            var deleteQuery = Self.baseQuery(id: id, service: oldService)
            if oldService == Self.userPresenceService {
                let context = LAContext()
                context.localizedReason = "Update KeyCourier approval protection"
                deleteQuery[kSecUseAuthenticationContext as String] = context
            }
            let deleteStatus = SecItemDelete(deleteQuery as CFDictionary)
            guard deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound else {
                throw KeyCourierError.keychainFailure(deleteStatus)
            }
        }.value
    }

    public func read(id: SecretID, reason: String) async throws -> Data? {
        try await Task.detached(priority: .userInitiated) {
            let context = LAContext()
            context.localizedReason = reason
            if let value = try Self.read(
                id: id,
                service: Self.approvalGatedService,
                context: nil
            ) {
                return value
            }
            return try Self.read(
                id: id,
                service: Self.userPresenceService,
                context: context
            )
        }.value
    }

    private static func read(id: SecretID, service: String, context: LAContext?) throws -> Data? {
            var query = Self.baseQuery(id: id, service: service)
            query[kSecMatchLimit as String] = kSecMatchLimitOne
            query[kSecReturnData as String] = true
            if let context {
                query[kSecUseAuthenticationContext as String] = context
            }

            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            if status == errSecItemNotFound { return nil }
            guard status == errSecSuccess else {
                throw KeyCourierError.keychainFailure(status)
            }
            guard let data = result as? Data else {
                throw KeyCourierError.unexpectedKeychainData
            }
            return data
    }

    public func delete(id: SecretID, reason: String) async throws {
        try await Task.detached(priority: .userInitiated) {
            let context = LAContext()
            context.localizedReason = reason
            for service in [Self.approvalGatedService, Self.userPresenceService] {
                var query = Self.baseQuery(id: id, service: service)
                if service == Self.userPresenceService {
                    query[kSecUseAuthenticationContext as String] = context
                }
                let status = SecItemDelete(query as CFDictionary)
                guard status == errSecSuccess || status == errSecItemNotFound else {
                    throw KeyCourierError.keychainFailure(status)
                }
            }
        }.value
    }

    private static func baseQuery(id: SecretID, service: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: id.rawValue,
            kSecAttrSynchronizable as String: false,
            kSecUseDataProtectionKeychain as String: true
        ]
    }
}

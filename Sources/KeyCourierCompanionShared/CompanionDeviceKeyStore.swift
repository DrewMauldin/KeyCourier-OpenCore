import Foundation
import Security

public struct CompanionDeviceIdentity: Equatable, Sendable {
    public let id: UUID
    public let keys: CompanionPrivateKeys

    public init(id: UUID, keys: CompanionPrivateKeys) {
        self.id = id
        self.keys = keys
    }
}

public struct CompanionDeviceKeyStore: Sendable {
    private static let service = "com.drewsdigest.KeyCourier.companion.device-identity"
    private static let deviceIDAccount = "device-id"
    private static let signingAccount = "signing-private-key"
    private static let agreementAccount = "agreement-private-key"
    private static let verifiedMacAccount = "verified-mac-agreement-public-key"
    private static let verifiedMacSigningAccount = "verified-mac-signing-public-key"

    public init() {}

    public func loadOrCreate() throws -> CompanionDeviceIdentity {
        let deviceIDData = try read(account: Self.deviceIDAccount)
        let signingData = try read(account: Self.signingAccount)
        let agreementData = try read(account: Self.agreementAccount)

        if let deviceIDData,
           let deviceIDString = String(data: deviceIDData, encoding: .utf8),
           let deviceID = UUID(uuidString: deviceIDString),
           let signingData,
           let agreementData,
           let keys = try? CompanionPrivateKeys(
               signingPrivateKey: signingData,
               keyAgreementPrivateKey: agreementData
           ) {
            return CompanionDeviceIdentity(id: deviceID, keys: keys)
        }

        try deleteAll()
        let identity = CompanionDeviceIdentity(id: UUID(), keys: CompanionCrypto.generatePrivateKeys())
        do {
            try save(Data(identity.id.uuidString.lowercased().utf8), account: Self.deviceIDAccount)
            try save(identity.keys.signingPrivateKey, account: Self.signingAccount)
            try save(identity.keys.keyAgreementPrivateKey, account: Self.agreementAccount)
            return identity
        } catch {
            try? deleteAll()
            throw error
        }
    }

    public func deleteAll() throws {
        let status = SecItemDelete(Self.baseQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw CompanionProtocolError.invalidRecord
        }
    }

    public func verifiedMacPublicKey() throws -> Data? {
        try read(account: Self.verifiedMacAccount)
    }

    public func saveVerifiedMacPublicKey(_ key: Data) throws {
        guard key.count == 32 else { throw CompanionProtocolError.invalidRecord }
        try delete(account: Self.verifiedMacAccount)
        try save(key, account: Self.verifiedMacAccount)
    }

    public func verifiedMacSigningPublicKey() throws -> Data? {
        try read(account: Self.verifiedMacSigningAccount)
    }

    public func saveVerifiedMacPublicKeys(agreement: Data, signing: Data) throws {
        guard agreement.count == 32, signing.count == 32 else {
            throw CompanionProtocolError.invalidRecord
        }
        try delete(account: Self.verifiedMacAccount)
        try delete(account: Self.verifiedMacSigningAccount)
        do {
            try save(agreement, account: Self.verifiedMacAccount)
            try save(signing, account: Self.verifiedMacSigningAccount)
        } catch {
            try? delete(account: Self.verifiedMacAccount)
            try? delete(account: Self.verifiedMacSigningAccount)
            throw error
        }
    }

    public func clearVerifiedMacPublicKey() throws {
        try delete(account: Self.verifiedMacAccount)
        try delete(account: Self.verifiedMacSigningAccount)
    }

    private func read(account: String) throws -> Data? {
        var query = Self.baseQuery
        query[kSecAttrAccount as String] = account
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnData as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw CompanionProtocolError.invalidRecord
        }
        return data
    }

    private func save(_ value: Data, account: String) throws {
        var query = Self.baseQuery
        query[kSecAttrAccount as String] = account
        query[kSecValueData as String] = value
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw CompanionProtocolError.invalidRecord }
    }

    private func delete(account: String) throws {
        var query = Self.baseQuery
        query[kSecAttrAccount as String] = account
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw CompanionProtocolError.invalidRecord
        }
    }

    private static var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrSynchronizable as String: false,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }
}

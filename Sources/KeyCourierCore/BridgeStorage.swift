import CryptoKit
import Foundation
import Security

public enum BridgeStorageError: Error, Equatable, LocalizedError, Sendable {
    case sharedContainerUnavailable
    case invalidIdentity
    case trustRevoked
    case keychainFailure(OSStatus)
    case unexpectedKeychainData

    public var errorDescription: String? {
        switch self {
        case .sharedContainerUnavailable:
            return "The KeyCourier bridge shared container is unavailable."
        case .invalidIdentity:
            return "The KeyCourier bridge identity is invalid."
        case .trustRevoked:
            return "KeyCourier bridge trust was revoked."
        case .keychainFailure:
            return "The KeyCourier bridge identity could not be stored securely."
        case .unexpectedKeychainData:
            return "The KeyCourier bridge identity store returned unexpected data."
        }
    }
}

public enum BridgeSharedContainer {
    public static let groupIdentifier = "T27WF6673W.com.drewsdigest.KeyCourier.bridge"

    public static func root(fileManager: FileManager = .default) throws -> URL {
        guard let container = fileManager.containerURL(
            forSecurityApplicationGroupIdentifier: groupIdentifier
        ) else {
            throw BridgeStorageError.sharedContainerUnavailable
        }
        return container.appending(path: "KeyCourierBridge", directoryHint: .isDirectory)
    }
}

public enum BridgeIdentityRole: String, Sendable {
    case store
    case bridge

    fileprivate var service: String {
        switch self {
        case .store:
            return "com.drewsdigest.KeyCourier.store.bridge-identity"
        case .bridge:
            return "com.drewsdigest.KeyCourierBridge.bridge-identity"
        }
    }
}

public struct BridgeIdentity: Equatable, Sendable {
    public let id: UUID
    public let keys: BridgePrivateKeys

    public init(id: UUID, keys: BridgePrivateKeys) {
        self.id = id
        self.keys = keys
    }
}

public struct BridgeKeychainIdentityStore: Sendable {
    private static let identityIDAccount = "identity-id"
    private static let signingAccount = "signing-private-key"
    private static let agreementAccount = "agreement-private-key"

    private let role: BridgeIdentityRole

    public init(role: BridgeIdentityRole) {
        self.role = role
    }

    public func loadOrCreate() throws -> BridgeIdentity {
        let idData = try read(account: Self.identityIDAccount)
        let signingData = try read(account: Self.signingAccount)
        let agreementData = try read(account: Self.agreementAccount)

        if let idData,
           let idString = String(data: idData, encoding: .utf8),
           let id = UUID(uuidString: idString),
           let signingData,
           let agreementData,
           let keys = try? BridgePrivateKeys(
               signingPrivateKey: signingData,
               keyAgreementPrivateKey: agreementData
           ) {
            return BridgeIdentity(id: id, keys: keys)
        }

        try deleteAll()
        let identity = BridgeIdentity(id: UUID(), keys: BridgeCrypto.generatePrivateKeys())
        do {
            try save(Data(identity.id.uuidString.lowercased().utf8), account: Self.identityIDAccount)
            try save(identity.keys.signingPrivateKey, account: Self.signingAccount)
            try save(identity.keys.keyAgreementPrivateKey, account: Self.agreementAccount)
            return identity
        } catch {
            try? deleteAll()
            throw error
        }
    }

    public func deleteAll() throws {
        let status = SecItemDelete(baseQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw BridgeStorageError.keychainFailure(status)
        }
    }

    private func read(account: String) throws -> Data? {
        var query = baseQuery
        query[kSecAttrAccount as String] = account
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnData as String] = true

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else {
            throw BridgeStorageError.keychainFailure(status)
        }
        guard let data = result as? Data else {
            throw BridgeStorageError.unexpectedKeychainData
        }
        return data
    }

    private func save(_ value: Data, account: String) throws {
        var query = baseQuery
        query[kSecAttrAccount as String] = account
        query[kSecValueData as String] = value
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw BridgeStorageError.keychainFailure(status)
        }
    }

    private var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: role.service,
            kSecAttrSynchronizable as String: false,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }
}

public struct BridgePinnedPeer: Codable, Equatable, Sendable {
    public let bridgeID: UUID
    public let signingPublicKey: Data
    public let keyAgreementPublicKey: Data?
    public let registrationDigest: Data

    public init(
        bridgeID: UUID,
        signingPublicKey: Data,
        keyAgreementPublicKey: Data? = nil,
        registrationDigest: Data
    ) throws {
        guard (try? Curve25519.Signing.PublicKey(rawRepresentation: signingPublicKey)) != nil,
              keyAgreementPublicKey.map({
                  (try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: $0)) != nil
              }) ?? true,
              registrationDigest.count == 32 else {
            throw BridgeStorageError.invalidIdentity
        }
        self.bridgeID = bridgeID
        self.signingPublicKey = signingPublicKey
        self.keyAgreementPublicKey = keyAgreementPublicKey
        self.registrationDigest = registrationDigest
    }

    private enum CodingKeys: String, CodingKey {
        case bridgeID
        case signingPublicKey
        case keyAgreementPublicKey
        case registrationDigest
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            bridgeID: container.decode(UUID.self, forKey: .bridgeID),
            signingPublicKey: container.decode(Data.self, forKey: .signingPublicKey),
            keyAgreementPublicKey: container.decodeIfPresent(Data.self, forKey: .keyAgreementPublicKey),
            registrationDigest: container.decode(Data.self, forKey: .registrationDigest)
        )
    }
}

public struct BridgePinnedPeerStore: Sendable {
    private static let service = "com.drewsdigest.KeyCourier.bridge.pinned-peer"
    private static let account = "peer"

    private let role: BridgeIdentityRole

    public init(role: BridgeIdentityRole) {
        self.role = role
    }

    public func load() throws -> BridgePinnedPeer? {
        guard let data = try read() else { return nil }
        do {
            return try JSONDecoder().decode(BridgePinnedPeer.self, from: data)
        } catch {
            throw BridgeStorageError.invalidIdentity
        }
    }

    public func save(_ peer: BridgePinnedPeer) throws {
        let encoder = JSONEncoder()
        let data = try encoder.encode(peer)
        var query = baseQuery
        query[kSecAttrAccount as String] = Self.account
        let updateStatus = SecItemUpdate(
            query as CFDictionary,
            [kSecValueData as String: data] as CFDictionary
        )
        if updateStatus == errSecSuccess { return }
        guard updateStatus == errSecItemNotFound else {
            throw BridgeStorageError.keychainFailure(updateStatus)
        }
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let addStatus = SecItemAdd(query as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw BridgeStorageError.keychainFailure(addStatus)
        }
    }

    public func delete() throws {
        var query = baseQuery
        query[kSecAttrAccount as String] = Self.account
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw BridgeStorageError.keychainFailure(status)
        }
    }

    private func read() throws -> Data? {
        var query = baseQuery
        query[kSecAttrAccount as String] = Self.account
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnData as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else {
            throw BridgeStorageError.keychainFailure(status)
        }
        guard let data = result as? Data else {
            throw BridgeStorageError.unexpectedKeychainData
        }
        return data
    }

    private var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "\(Self.service).\(role.rawValue)",
            kSecAttrSynchronizable as String: false,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }
}

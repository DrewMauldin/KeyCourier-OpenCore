import Foundation
import Security

private enum AdapterError: Error {
    case invalidArguments
    case invalidValue
    case keychain(OSStatus)
    case verificationFailed
}

private let maximumSecretBytes = 64 * 1024
private let allowedNameCharacters = CharacterSet(
    charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
)

private func validatedName(_ value: String) throws -> String {
    guard !value.isEmpty,
          value.count <= 256,
          value.unicodeScalars.allSatisfy(allowedNameCharacters.contains) else {
        throw AdapterError.invalidArguments
    }
    return value
}

private func baseQuery(service: String, account: String) -> [CFString: Any] {
    [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: service,
        kSecAttrAccount: account,
        kSecAttrSynchronizable: kCFBooleanFalse as Any,
    ]
}

private func read(service: String, account: String) throws -> Data? {
    var query = baseQuery(service: service, account: account)
    query[kSecReturnData] = kCFBooleanTrue
    query[kSecMatchLimit] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound { return nil }
    guard status == errSecSuccess else { throw AdapterError.keychain(status) }
    guard let data = result as? Data else { throw AdapterError.verificationFailed }
    return data
}

private func save(_ value: Data, service: String, account: String) throws {
    if let previous = try read(service: service, account: account) {
        let backupService = service + ".keycourier.previous"
        try upsert(previous, service: backupService, account: account)
    }
    try upsert(value, service: service, account: account)
    guard try read(service: service, account: account) == value else {
        throw AdapterError.verificationFailed
    }
}

private func upsert(_ value: Data, service: String, account: String) throws {
    let query = baseQuery(service: service, account: account)
    let update: [CFString: Any] = [kSecValueData: value]
    let updateStatus = SecItemUpdate(query as CFDictionary, update as CFDictionary)
    if updateStatus == errSecSuccess { return }
    guard updateStatus == errSecItemNotFound else { throw AdapterError.keychain(updateStatus) }
    var addition = query
    addition[kSecValueData] = value
    addition[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    let addStatus = SecItemAdd(addition as CFDictionary, nil)
    guard addStatus == errSecSuccess else { throw AdapterError.keychain(addStatus) }
}

do {
    let arguments = Array(CommandLine.arguments.dropFirst())
    guard arguments.count == 3, arguments[0] == "upsert" else {
        throw AdapterError.invalidArguments
    }
    let service = try validatedName(arguments[1])
    let account = try validatedName(arguments[2])
    let value = FileHandle.standardInput.readDataToEndOfFile()
    guard !value.isEmpty,
          value.count <= maximumSecretBytes,
          !value.contains(0) else {
        throw AdapterError.invalidValue
    }
    try save(value, service: service, account: account)
    FileHandle.standardOutput.write(Data("{\"verified\":true}\n".utf8))
} catch {
    exit(1)
}

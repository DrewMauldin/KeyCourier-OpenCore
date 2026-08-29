import Foundation

public struct DotenvInstaller: Sendable {
    private static let maximumFileBytes = 1024 * 1024
    private static let maximumSecretBytes = 64 * 1024

    public init() {}

    public func install(_ secret: Data, for profile: ConsumerProfile) throws -> DeliveryResult {
        guard case .dotenv(let path, let variable) = profile.destination else {
            throw KeyCourierError.unsupportedDestination
        }
        guard !secret.isEmpty,
              secret.count <= Self.maximumSecretBytes,
              let value = String(data: secret, encoding: .utf8),
              !value.contains("\n"),
              !value.contains("\r"),
              !value.contains("\0") else {
            throw KeyCourierError.malformedSecretValue
        }

        let destination = URL(filePath: path).standardizedFileURL
        let parent = destination.deletingLastPathComponent()
        guard parent.path != "/" else {
            throw KeyCourierError.malformedDestination
        }

        let existingData: Data
        if try SecureFileSystem.fileExists(destination) {
            existingData = try SecureFileSystem.readRegularFile(
                destination,
                maximumBytes: Self.maximumFileBytes
            )
        } else {
            existingData = Data()
        }
        guard let existing = String(data: existingData, encoding: .utf8) else {
            throw KeyCourierError.malformedDestination
        }

        let updated = try replacing(variable: variable, with: value, in: existing)
        var backupPath: String?
        if !existingData.isEmpty {
            let backup = URL(filePath: destination.path + ".keycourier.previous")
            try SecureFileSystem.writeAtomically(
                existingData,
                to: backup,
                directoryPolicy: .existingOwnerControlled
            )
            backupPath = backup.path
        }
        try SecureFileSystem.writeAtomically(
            Data(updated.utf8),
            to: destination,
            directoryPolicy: .existingOwnerControlled
        )
        return DeliveryResult(backupPath: backupPath)
    }

    public func install(
        username: String,
        password: Data,
        for profile: ConsumerProfile
    ) throws -> DeliveryResult {
        guard case .dotenvLogin(let path, let usernameVariable, let passwordVariable) = profile.destination,
              let passwordValue = String(data: password, encoding: .utf8) else {
            throw KeyCourierError.unsupportedDestination
        }
        let username = try validatedValue(Data(username.utf8))
        let password = try validatedValue(Data(passwordValue.utf8))
        let destination = URL(filePath: path).standardizedFileURL
        let parent = destination.deletingLastPathComponent()
        guard parent.path != "/" else { throw KeyCourierError.malformedDestination }

        let existingData: Data
        if try SecureFileSystem.fileExists(destination) {
            existingData = try SecureFileSystem.readRegularFile(
                destination,
                maximumBytes: Self.maximumFileBytes
            )
        } else {
            existingData = Data()
        }
        guard let existing = String(data: existingData, encoding: .utf8) else {
            throw KeyCourierError.malformedDestination
        }
        let withUsername = try replacing(variable: usernameVariable, with: username, in: existing)
        let updated = try replacing(variable: passwordVariable, with: password, in: withUsername)
        var backupPath: String?
        if !existingData.isEmpty {
            let backup = URL(filePath: destination.path + ".keycourier.previous")
            try SecureFileSystem.writeAtomically(
                existingData,
                to: backup,
                directoryPolicy: .existingOwnerControlled
            )
            backupPath = backup.path
        }
        try SecureFileSystem.writeAtomically(
            Data(updated.utf8),
            to: destination,
            directoryPolicy: .existingOwnerControlled
        )
        return DeliveryResult(backupPath: backupPath)
    }

    private func validatedValue(_ data: Data) throws -> String {
        guard !data.isEmpty,
              data.count <= Self.maximumSecretBytes,
              let value = String(data: data, encoding: .utf8),
              !value.contains("\n"),
              !value.contains("\r"),
              !value.contains("\0") else {
            throw KeyCourierError.malformedSecretValue
        }
        return value
    }

    private func replacing(variable: String, with value: String, in contents: String) throws -> String {
        var lines = contents.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        if lines.last == "" { lines.removeLast() }

        let matchingIndexes = lines.indices.filter { index in
            let trimmed = lines[index].trimmingCharacters(in: .whitespaces)
            return trimmed.hasPrefix("\(variable)=")
        }
        guard matchingIndexes.count <= 1 else {
            throw KeyCourierError.malformedDestination
        }

        let replacement = "\(variable)=\"\(escaped(value))\""
        if let index = matchingIndexes.first {
            lines[index] = replacement
        } else {
            lines.append(replacement)
        }
        return lines.joined(separator: "\n") + "\n"
    }

    private func escaped(_ value: String) -> String {
        value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "$", with: "$$")
    }
}

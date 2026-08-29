import Foundation

public enum ConsumerDestination: Codable, Equatable, Sendable {
    case dotenv(path: String, variable: String)
    case dotenvLogin(path: String, usernameVariable: String, passwordVariable: String)
    case remoteAge(profile: String)
}

public struct ConsumerProfile: Codable, Equatable, Identifiable, Sendable {
    public let id: ConsumerID
    public var displayName: String
    public let targetID: TargetID
    public let destination: ConsumerDestination

    public init(
        id: ConsumerID,
        displayName: String,
        targetID: TargetID,
        destination: ConsumerDestination
    ) throws {
        let trimmedName = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedName.isEmpty, trimmedName.count <= 80 else {
            throw KeyCourierError.malformedDestination
        }
        try Self.validate(destination)
        self.id = id
        self.displayName = trimmedName
        self.targetID = targetID
        self.destination = destination
    }

    private static func validate(_ destination: ConsumerDestination) throws {
        switch destination {
        case .dotenv(let path, let variable):
            guard path.hasPrefix("/"),
                  !path.contains("\0"),
                  path.count <= 1024,
                  Self.validVariable(variable) else {
                throw KeyCourierError.malformedDestination
            }
        case .dotenvLogin(let path, let usernameVariable, let passwordVariable):
            guard path.hasPrefix("/"),
                  !path.contains("\0"),
                  path.count <= 1024,
                  usernameVariable != passwordVariable,
                  Self.validVariable(usernameVariable),
                  Self.validVariable(passwordVariable) else {
                throw KeyCourierError.malformedDestination
            }
        case .remoteAge(let profile):
            guard (try? IdentifierValidatorProxy.validate(profile)) != nil else {
                throw KeyCourierError.malformedDestination
            }
        }
    }

    private static func validVariable(_ variable: String) -> Bool {
        variable.count <= 128 &&
        variable.first.map({ $0 == "_" || $0.isLetter }) == true &&
        variable.allSatisfy({ $0 == "_" || $0.isUppercase || $0.isNumber })
    }
}

private enum IdentifierValidatorProxy {
    static func validate(_ value: String) throws {
        _ = try ConsumerID(validating: value)
    }
}

public struct DeliveryResult: Equatable, Sendable {
    public let backupPath: String?

    public init(backupPath: String?) {
        self.backupPath = backupPath
    }
}

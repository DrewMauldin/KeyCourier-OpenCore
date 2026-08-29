import Foundation

public enum AgentCommandError: Error, LocalizedError, Equatable {
    case invalidUsage
    case missingOption(String)
    case duplicateOption(String)
    case unknownOption(String)
    case invalidClient
    case invalidDestination
    case invalidRequestID

    public var errorDescription: String? {
        switch self {
        case .invalidUsage: "Use request, status REQUEST_ID, secrets, consumers or doctor."
        case .missingOption(let option): "Missing required option: \(option)."
        case .duplicateOption(let option): "Option supplied more than once: \(option)."
        case .unknownOption(let option): "Unknown or prohibited option: \(option)."
        case .invalidClient: "Client must be codex, claude or opencode."
        case .invalidDestination: "Destination must be this-mac, mac-mini or vps."
        case .invalidRequestID: "Status requires a valid request UUID."
        }
    }
}

public enum AgentCommand: Equatable, Sendable {
    case request(SecretRequest)
    case status(UUID)
    case secrets
    case consumers
    case doctor

    public static func parse(arguments: [String]) throws -> AgentCommand {
        guard let verb = arguments.first else {
            throw AgentCommandError.invalidUsage
        }
        switch verb {
        case "request":
            return try parseRequest(Array(arguments.dropFirst()))
        case "status":
            guard arguments.count == 2, let id = UUID(uuidString: arguments[1]) else {
                throw AgentCommandError.invalidRequestID
            }
            return .status(id)
        case "secrets":
            guard arguments.count == 1 else { throw AgentCommandError.invalidUsage }
            return .secrets
        case "consumers":
            guard arguments.count == 1 else { throw AgentCommandError.invalidUsage }
            return .consumers
        case "doctor":
            guard arguments.count == 1 else { throw AgentCommandError.invalidUsage }
            return .doctor
        default:
            throw AgentCommandError.invalidUsage
        }
    }

    private static func parseRequest(_ arguments: [String]) throws -> AgentCommand {
        let allowed = Set(["--client", "--destination", "--secret-id", "--target", "--consumer", "--reason"])
        guard arguments.count.isMultiple(of: 2) else {
            throw AgentCommandError.invalidUsage
        }

        var options: [String: String] = [:]
        var index = 0
        while index < arguments.count {
            let option = arguments[index]
            guard allowed.contains(option) else {
                throw AgentCommandError.unknownOption(option)
            }
            guard options[option] == nil else {
                throw AgentCommandError.duplicateOption(option)
            }
            options[option] = arguments[index + 1]
            index += 2
        }

        func required(_ option: String) throws -> String {
            guard let value = options[option] else {
                throw AgentCommandError.missingOption(option)
            }
            return value
        }

        guard let client = AgentClient(rawValue: try required("--client")) else {
            throw AgentCommandError.invalidClient
        }

        if let destinationValue = options["--destination"] {
            guard options["--secret-id"] == nil,
                  options["--target"] == nil,
                  options["--consumer"] == nil else {
                throw AgentCommandError.invalidUsage
            }
            guard let destination = GuidedDestination(rawValue: destinationValue) else {
                throw AgentCommandError.invalidDestination
            }
            return .request(try SecretRequest(
                client: client,
                secretID: SecretID(validating: destination.secretIDValue),
                targetID: TargetID(validating: destination.targetIDValue),
                consumerID: ConsumerID(validating: destination.consumerIDValue),
                reason: try required("--reason")
            ))
        }

        return .request(try SecretRequest(
            client: client,
            secretID: SecretID(validating: try required("--secret-id")),
            targetID: TargetID(validating: try required("--target")),
            consumerID: ConsumerID(validating: try required("--consumer")),
            reason: try required("--reason")
        ))
    }
}

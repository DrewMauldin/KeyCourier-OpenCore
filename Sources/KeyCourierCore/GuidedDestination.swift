import Foundation

public enum GuidedDestination: String, CaseIterable, Identifiable, Sendable {
    case thisMac = "this-mac"
    case macMini = "mac-mini"
    case vps
    case cloudMemoryProjection = "cloud-memory-projection"

    public static let remoteCases: [GuidedDestination] = [.macMini, .vps]

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .thisMac: "This Mac"
        case .macMini: "Mac Mini"
        case .vps: "VPS"
        case .cloudMemoryProjection: "Cloud Memory Projection Executor"
        }
    }

    public var secretIDValue: String { "\(rawValue)-secret" }
    public var consumerIDValue: String { rawValue }
    public var targetIDValue: String {
        switch self {
        case .cloudMemoryProjection: "vps"
        default: rawValue
        }
    }

    public var secretDisplayName: String { "\(displayName) secret" }

    public func consumerProfile(directories: AppDirectories = .standard) throws -> ConsumerProfile {
        let destination: ConsumerDestination = switch self {
        case .thisMac:
            .dotenv(
                path: directories.installations.appending(path: "this-mac.env").path,
                variable: "KEYCOURIER_SECRET"
            )
        case .macMini, .vps, .cloudMemoryProjection:
            .remoteAge(profile: consumerIDValue)
        }
        return try ConsumerProfile(
            id: ConsumerID(validating: consumerIDValue),
            displayName: displayName,
            targetID: TargetID(validating: targetIDValue),
            destination: destination
        )
    }

    public static func matching(
        secretID: SecretID,
        consumerID: ConsumerID,
        targetID: TargetID
    ) -> GuidedDestination? {
        allCases.first {
            $0.secretIDValue == secretID.rawValue
                && $0.consumerIDValue == consumerID.rawValue
                && $0.targetIDValue == targetID.rawValue
        }
    }

    public static func matching(consumerID: ConsumerID, targetID: TargetID) -> GuidedDestination? {
        allCases.first {
            $0.consumerIDValue == consumerID.rawValue && $0.targetIDValue == targetID.rawValue
        }
    }
}

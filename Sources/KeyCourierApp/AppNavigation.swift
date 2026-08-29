import KeyCourierCore

enum SidebarSection: String, CaseIterable, Identifiable {
    case home = "Home"
    case requests = "Approvals"
    case credentials = "Credentials"
    case history = "Activity"
    case settings = "Settings"
    case advanced = "Advanced"

    var id: Self { self }

    var systemImage: String {
        switch self {
        case .home: "house"
        case .requests: "tray.full"
        case .credentials: "key"
        case .history: "clock.arrow.circlepath"
        case .settings: "gearshape"
        case .advanced: "gearshape.2"
        }
    }
}

enum DestinationRegistration {
    case registered
    case conflict
    case missing
}

struct DestinationSummary: Identifiable {
    let destination: GuidedDestination
    let registration: DestinationRegistration

    var id: GuidedDestination { destination }
}

import Foundation
import UserNotifications

struct RequestNotificationService {
    private let centre = UNUserNotificationCenter.current()

    func requestPermission() async -> Bool {
        (try? await centre.requestAuthorization(options: [.alert, .sound, .badge])) == true
    }

    func isAuthorised() async -> Bool {
        let settings = await centre.notificationSettings()
        return settings.authorizationStatus == .authorized || settings.authorizationStatus == .provisional
    }

    func notifyPending(destination: String) async {
        let content = UNMutableNotificationContent()
        content.title = "Approval requested"
        content.body = "KeyCourier is waiting to deliver a credential to \(destination)."
        content.sound = .default
        let request = UNNotificationRequest(
            identifier: "keycourier-pending-\(UUID().uuidString)",
            content: content,
            trigger: nil
        )
        try? await centre.add(request)
    }

    func notifyCompleted(destination: String, wasDelivered: Bool) async {
        let content = UNMutableNotificationContent()
        content.title = wasDelivered ? "Delivery confirmed" : "Request completed"
        content.body = wasDelivered
            ? "\(destination) confirmed the credential installation."
            : "The KeyCourier request for \(destination) was not delivered."
        let request = UNNotificationRequest(
            identifier: "keycourier-complete-\(UUID().uuidString)",
            content: content,
            trigger: nil
        )
        try? await centre.add(request)
    }
}

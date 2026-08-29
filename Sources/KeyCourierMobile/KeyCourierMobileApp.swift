import SwiftUI
import UIKit
import UserNotifications

@main
struct KeyCourierMobileApp: App {
    @UIApplicationDelegateAdaptor(CompanionAppDelegate.self) private var appDelegate
    @State private var model = CompanionAppModel()

    var body: some Scene {
        WindowGroup {
            CompanionRootView(model: model)
                .task { await model.refresh() }
                .onReceive(NotificationCenter.default.publisher(for: .keyCourierRemoteChange)) { _ in
                    Task { await model.refresh() }
                }
        }
    }
}

final class CompanionAppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        return true
    }

    func application(
        _ application: UIApplication,
        didReceiveRemoteNotification userInfo: [AnyHashable: Any],
        fetchCompletionHandler completionHandler: @escaping (UIBackgroundFetchResult) -> Void
    ) {
        NotificationCenter.default.post(name: .keyCourierRemoteChange, object: nil)
        completionHandler(.newData)
    }

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification
    ) async -> UNNotificationPresentationOptions {
        NotificationCenter.default.post(name: .keyCourierRemoteChange, object: nil)
        return [.banner, .sound, .badge]
    }
}

extension Notification.Name {
    static let keyCourierRemoteChange = Notification.Name("KeyCourierRemoteChange")
}

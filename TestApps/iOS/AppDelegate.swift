// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import UIKit

@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?

    private var testViewController: TestViewController {
        window!.rootViewController as! TestViewController
    }

    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        return true
    }

    func applicationDidBecomeActive(_: UIApplication) {
        NSLog("Test application did become active.")
    }

    func applicationWillResignActive(_: UIApplication) {
        NSLog("Test application is about to become inactive.")
    }

    func applicationDidEnterBackground(_: UIApplication) {
        NSLog("Test application did enter background.")
    }

    func applicationWillEnterForeground(_: UIApplication) {
        NSLog("Test application is about to enter the foreground.")
    }

    func applicationWillTerminate(_: UIApplication) {
        NSLog("Test application is about to terminate.")
    }

    // MARK: - Remote Notifications
    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        testViewController.didReceiveDeviceToken(deviceToken)
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        testViewController.didFailToRegisterForRemoteNotificationsWithError(error)
    }

    func application(_ application: UIApplication, didReceiveRemoteNotification userInfo: [AnyHashable: Any], fetchCompletionHandler completionHandler: @escaping (UIBackgroundFetchResult) -> Void) {
        testViewController.didReceiveBackgroundNotification(userInfo: userInfo)
        completionHandler(.newData)
    }
}

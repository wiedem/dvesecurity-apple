// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import XCTest

class Keychain_BackgroundQueryTestsDevice: InteractiveTestCaseDevice {
    private let password = "Password-1234!äöü/"
    private let account = "InternetPasswordTest"

    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .internetPassword)
    }

    #if os(iOS)
    func testQueryInBackgroundNotification() throws {
        let accessControl = Keychain.AccessControl(itemAccessibility: .whenUnlockedThisDeviceOnly)

        try Keychain.InternetPassword.save(password, forAccount: account, accessControl: accessControl)

        testViewModel.stopActivity()
        testViewModel.setTestTitle("Test Query in Background Push Notification")

        testViewModel.addTestDescription("Enable remote notifications, send the app in the background, make sure your device is not locked, send a background notification and wait for the notification to arrive.")

        // This test requires that the remote notifications are allowed for the test app and that you are able to send
        // push notifications to the device.
        // The device token will be printed to the console and can be copied from there.
        let password = try wait(description: "Keychain query", timeout: Self.veryLongUIInteractionTimeout) { (completion: @escaping AsyncResultCompletionHandler<String?>) in
            self.testViewModel.enableRemoteNotifications { backgroundNotification, _ in
                guard backgroundNotification else {
                    completion(.failure(TestError.receivedForegroundNotification))
                    return
                }
                Keychain.InternetPassword.queryOne(forAccount: self.account, completion: completion)
            }
        }
        expect(password) == self.password
    }

    func testQueryInBackgroundNotificationWithLockedDevice() throws {
        let accessControl = Keychain.AccessControl(itemAccessibility: .whenUnlockedThisDeviceOnly)

        try Keychain.InternetPassword.save(password, forAccount: account, accessControl: accessControl)

        testViewModel.stopActivity()
        testViewModel.setTestTitle("Test Query in Background Push Notification")

        testViewModel.addTestDescription("Enable remote notifications, lock your device, send a background notification and wait for the notification to arrive.")

        // This test requires that the remote notifications are allowed for the test app and that you are able to send
        // push notifications to the device.
        // The device token will be printed to the console and can be copied from there.
        expect {
            _ = try self.wait(description: "Keychain query", timeout: Self.veryLongUIInteractionTimeout) { (completion: @escaping AsyncResultCompletionHandler<String?>) in
                self.testViewModel.enableRemoteNotifications { backgroundNotification, _ in
                    guard backgroundNotification else {
                        completion(.failure(TestError.receivedForegroundNotification))
                        return
                    }
                    Keychain.InternetPassword.queryOne(forAccount: self.account, completion: completion)
                }
            }
        }.to(throwError {
            expect($0) == KeychainError.itemQueryFailed(status: errSecInteractionNotAllowed)
        })
    }
    #endif
}

private enum TestError: Error {
    case receivedForegroundNotification
}

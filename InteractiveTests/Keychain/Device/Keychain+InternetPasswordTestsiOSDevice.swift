// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import LocalAuthentication
import Nimble
import XCTest

class Keychain_InternetPasswordTestsiOSDevice: InteractiveTestCaseDevice {
    private let password = "Password-1234!äöü/"
    private let account = "InternetPasswordTest"

    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .internetPassword)
    }

    func testQueryWithApplicationPassword() throws {
        let accessControl = Keychain.AccessControl(
            itemAccessibility: .afterFirstUnlockThisDeviceOnly,
            flags: [.applicationPassword(prompt: "Specify a password for the protected access to the keychain")]
        )

        try Keychain.InternetPassword.save(password, forAccount: account, accessControl: accessControl)
        // Manual confirmation is necessary for this test because we can't know if the user entered the proper password or if the authentication UI did appear properly.
        let authentication = Keychain.QueryAuthentication(userInterface: .allow(prompt: "Password for the protected access to the keychain item"))
        let result = wait(expectationDescription: "Keychain query", timeout: Self.defaultUIInteractionTimeout) { expectation in
            Keychain.InternetPassword.queryOne(forAccount: self.account, authentication: authentication) { result in
                defer { expectation?.fulfill() }
                switch result {
                case .success: break
                case let .failure(error): fail("Failed to query password: \(error)")
                }
            }
        }
        guard result.isCompleted else { return }
    }
}

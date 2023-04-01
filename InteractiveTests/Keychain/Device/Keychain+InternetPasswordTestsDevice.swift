// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import LocalAuthentication
import Nimble
import XCTest

final class Keychain_InternetPasswordTestsDevice: InteractiveTestCaseDevice {
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
        let password = try wait(description: "Keychain query", timeout: Self.defaultUIInteractionTimeout) {
            Keychain.InternetPassword.queryOne(forAccount: self.account, authentication: authentication, completion: $0)
        }
        expect(password) == self.password
    }
}

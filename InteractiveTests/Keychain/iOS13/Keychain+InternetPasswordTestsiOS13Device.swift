// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import LocalAuthentication
import Nimble
import XCTest

@available(iOS 13.0, *)
final class Keychain_InternetPasswordTestsiOS13Device: InteractiveTestCaseiOS13Device {
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
        _ = try Keychain.InternetPassword.queryOne(forAccount: account, authentication: authentication)
    }

    func testQueryWithUserPresence() throws {
        let authenticationContext = LAContext()
        var error: NSError?
        guard authenticationContext.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            throw XCTSkip("Device not prepared properly for tests, make sure a passcode is set on the device.")
        }

        try Keychain.InternetPassword.save(
            password,
            forAccount: account,
            accessControl: .init(itemAccessibility: .afterFirstUnlockThisDeviceOnly, flags: [.userPresence])
        )
        // Manual confirmation is necessary for this test because we can't know if the user entered the proper password or if the authentication UI did appear properly.
        _ = try Keychain.InternetPassword.queryOne(forAccount: account)
    }

    func testQueryWithAuthenticationContext() throws {
        continueAfterFailure = false

        let authenticationContext = LAContext()
        var error: NSError?
        guard authenticationContext.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            throw XCTSkip("Device not prepared properly for tests, make sure Touch ID or Face ID is available and activated.")
        }

        var policyEvaluationError: Error?
        let result = wait(expectationDescription: "Policy evaluation", timeout: Self.defaultUIInteractionTimeout) { expectation in
            authenticationContext.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Touch ID / Face ID for InternetPasswordTests") { _, error in
                policyEvaluationError = error
                expectation?.fulfill()
            }
        }
        guard result.isCompleted else { return }
        expect(policyEvaluationError).to(beNil())

        try Keychain.InternetPassword.save(
            password,
            forAccount: account,
            accessControl: .init(itemAccessibility: .afterFirstUnlockThisDeviceOnly, flags: [.biometryAny])
        )

        let queryAuthentication = Keychain.QueryAuthentication(authenticationContext: authenticationContext, userInterface: .disallow)
        _ = try Keychain.InternetPassword.queryOne(forAccount: account, authentication: queryAuthentication)
    }
}

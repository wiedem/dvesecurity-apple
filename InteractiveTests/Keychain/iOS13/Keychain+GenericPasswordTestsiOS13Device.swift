// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import LocalAuthentication
import Nimble
import XCTest

@available(iOS 13.0, *)
class Keychain_GenericPasswordTestsiOS13Device: InteractiveTestCaseiOS13Device {
    private let password = "Password-1234!äöü/"
    private let account = "GenericPasswordTest"
    private let service = "com.diva-e.tests.GenericPasswordTests"

    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .genericPassword)
    }

    func testQueryWithApplicationPassword() throws {
        let accessControl = Keychain.AccessControl(
            itemAccessibility: .afterFirstUnlockThisDeviceOnly,
            flags: [.applicationPassword(prompt: "Specify a password for the protected access to the keychain")]
        )

        try Keychain.GenericPassword.save(password, forAccount: account, service: service, accessControl: accessControl)
        // Manual confirmation is necessary for this test because we can't know if the user entered the proper password or if the authentication UI did appear properly.
        let authentication = Keychain.QueryAuthentication(userInterface: .allow(prompt: "Password for the protected access to the keychain item"))
        _ = try Keychain.GenericPassword.query(forAccount: account, service: service, authentication: authentication)
    }

    func testQueryWithUserPresence() throws {
        let authenticationContext = LAContext()
        var error: NSError?
        guard authenticationContext.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            throw XCTSkip("Device not prepared properly for tests, make sure a passcode is set on the device.")
        }

        try Keychain.GenericPassword.save(
            password,
            forAccount: account,
            service: service,
            accessControl: .init(itemAccessibility: .afterFirstUnlockThisDeviceOnly, flags: [.userPresence])
        )
        _ = try Keychain.GenericPassword.query(forAccount: account, service: service)
    }

    func testQueryWithAuthenticationContext() throws {
        continueAfterFailure = false

        let authenticationContext = LAContext()
        var error: NSError?
        guard authenticationContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            throw error!
        }

        var policyEvaluationError: Error?
        let result = wait(expectationDescription: "Policy evaluation", timeout: Self.defaultUIInteractionTimeout) { expectation in
            authenticationContext
                .evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Touch ID / Face ID for GenericPasswordTests") { _, error in
                    policyEvaluationError = error
                    expectation?.fulfill()
                }
        }
        guard result.isCompleted else { return }
        expect(policyEvaluationError).to(beNil())

        let queryAuthentication = Keychain.QueryAuthentication(authenticationContext: authenticationContext, userInterface: .disallow)
        try Keychain.GenericPassword.save(
            password,
            forAccount: account,
            service: service,
            accessControl: .init(itemAccessibility: .afterFirstUnlockThisDeviceOnly, flags: [.biometryAny])
        )
        _ = try Keychain.GenericPassword.query(forAccount: account, service: service, authentication: queryAuthentication)
    }
}

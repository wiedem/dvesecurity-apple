// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import LocalAuthentication
import Nimble
import XCTest

@available(iOS 13.0, *)
final class Keychain_AESTestsiOS13Device: InteractiveTestCaseiOS13Device {
    // swiftlint:disable:next force_try
    private lazy var key: Crypto.AES.Key = try! Crypto.AES.Key(
        keySize: .bits256,
        password: "Hello Test!",
        withSalt: "Salt",
        pseudoRandomAlgorithm: .hmacAlgSHA256,
        rounds: 1
    )

    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .key)
    }

    func testQueryWithApplicationPassword() throws {
        let keyTag = "Test Tag \(#function)"
        let applicationLabel = "Test ApplicationLabel \(#function)".data(using: .utf8)
        let accessControl = Keychain.AccessControl(
            itemAccessibility: .afterFirstUnlockThisDeviceOnly,
            flags: [.applicationPassword(prompt: "Specify a password for the protected access to the keychain")]
        )

        try Keychain.saveKey(key, withTag: keyTag, applicationLabel: applicationLabel, accessControl: accessControl)
        let authentication = Keychain.QueryAuthentication(userInterface: .allow(prompt: "Password for the protected access to the keychain item"))
        let _: Crypto.AES.Key? = try Keychain.queryKey(withTag: keyTag, applicationLabel: applicationLabel, authentication: authentication)
    }

    func testQueryWithUserPresence() throws {
        let keyTag = "Test Tag \(#function)"
        let applicationLabel = "Test ApplicationLabel \(#function)".data(using: .utf8)

        let authenticationContext = LAContext()
        var error: NSError?
        guard authenticationContext.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            throw XCTSkip("Device not prepared properly for tests, make sure a passcode is set on the device.")
        }

        try Keychain.saveKey(
            key,
            withTag: keyTag,
            applicationLabel: applicationLabel,
            accessControl: .init(itemAccessibility: .afterFirstUnlockThisDeviceOnly, flags: [.userPresence])
        )
        // Manual confirmation is necessary for this test because we can't know if the user entered the proper password or if the authentication UI did appear properly.
        let _: Crypto.AES.Key? = try Keychain.queryKey(withTag: keyTag, applicationLabel: applicationLabel)
    }

    func testQueryWithAuthenticationContext() throws {
        continueAfterFailure = false

        let keyTag = "Test Tag \(#function)"
        let applicationLabel = "Test ApplicationLabel \(#function)".data(using: .utf8)

        let authenticationContext = LAContext()
        var error: NSError?
        guard authenticationContext.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            throw error!
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

        try Keychain.saveKey(
            key,
            withTag: keyTag,
            applicationLabel: applicationLabel,
            accessControl: .init(itemAccessibility: .afterFirstUnlockThisDeviceOnly, flags: [.userPresence])
        )

        let authentication = Keychain.QueryAuthentication(authenticationContext: authenticationContext, userInterface: .disallow)
        let _: Crypto.AES.Key? = try Keychain.queryKey(withTag: keyTag, applicationLabel: applicationLabel, authentication: authentication)
    }
}

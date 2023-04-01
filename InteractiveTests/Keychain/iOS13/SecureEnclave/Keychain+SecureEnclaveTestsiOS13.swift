// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import CryptoKit
import LocalAuthentication
import Nimble
import XCTest

@available(iOS 13.0, *)
final class Keychain_SecureEnclaveTestsiOS13: InteractiveTestCaseiOS13Device {
    override func setUpWithError() throws {
        try super.setUpWithError()

        guard CryptoKit.SecureEnclave.isAvailable else {
            throw XCTSkip("Test case needs to run on device with Secure Enclave support.")
        }
    }

    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .key)
    }

    func testQueryWithApplicationPassword() throws {
        let keyTag = "Test Tag \(#function)"
        let accessControl = Keychain.AccessControl(
            itemAccessibility: .afterFirstUnlockThisDeviceOnly,
            flags: [.applicationPassword(prompt: "Specify a password for the protected access to the keychain")]
        )

        _ = try Crypto.ECC.SecureEnclaveKey(inKeychainWithTag: keyTag, accessControl: accessControl)
        let authentication = Keychain.QueryAuthentication(userInterface: .allow(prompt: "Password for the protected access to the keychain item"))
        _ = try Keychain.queryKey(withTag: keyTag, authentication: authentication) as Crypto.ECC.SecureEnclaveKey?
    }

    func testQueryWithUserPresence() throws {
        let keyTag = "Test Tag \(#function)"
        let accessControl = Keychain.AccessControl(itemAccessibility: .afterFirstUnlockThisDeviceOnly, flags: [.userPresence])

        let authenticationContext = LAContext()
        var error: NSError?
        guard authenticationContext.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            throw XCTSkip("Device not prepared properly for tests, make sure a passcode is set on the device.")
        }

        _ = try Crypto.ECC.SecureEnclaveKey(inKeychainWithTag: keyTag, accessControl: accessControl)
        // Manual confirmation is necessary for this test because we can't know if the user entered the proper password or if the authentication UI did appear properly.
        _ = try Keychain.queryKey(withTag: keyTag) as Crypto.ECC.SecureEnclaveKey?
    }

    func testQueryWithAuthenticationContext() throws {
        continueAfterFailure = false

        let keyTag = "Test Tag \(#function)"
        let accessControl = Keychain.AccessControl(itemAccessibility: .afterFirstUnlockThisDeviceOnly, flags: [.userPresence])

        let authenticationContext = LAContext()
        var error: NSError?
        guard authenticationContext.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            throw XCTSkip("Device not prepared properly for tests, make sure a passcode is set on the device.")
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

        _ = try Crypto.ECC.SecureEnclaveKey(inKeychainWithTag: keyTag, accessControl: accessControl)
        let authentication = Keychain.QueryAuthentication(authenticationContext: authenticationContext, userInterface: .disallow)
        _ = try Keychain.queryKey(withTag: keyTag, authentication: authentication) as Crypto.ECC.SecureEnclaveKey?
    }
}

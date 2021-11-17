// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import LocalAuthentication
import Nimble
import XCTest

@available(iOS 13.0, *)
class Keychain_ECCTestsiOS13Device: InteractiveTestCaseiOS13Device {
    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .key)
    }

    func testQueryWithApplicationPassword() throws {
        let keyTag = "Test Tag \(#function)"
        let privateKey = Crypto.ECC.PrivateKey(curve: .P256)
        let publicKey: Crypto.ECC.PublicKey = privateKey.publicKey()
        let accessControl = Keychain.AccessControl(
            itemAccessibility: .afterFirstUnlockThisDeviceOnly,
            flags: [.applicationPassword(prompt: "Specify a password for the protected access to the keychain")]
        )

        try Keychain.saveKey(privateKey, withTag: keyTag, accessControl: accessControl)
        let authentication = Keychain.QueryAuthentication(userInterface: .allow(prompt: "Password for the protected access to the keychain item"))
        _ = try Keychain.queryKey(for: publicKey, authentication: authentication) as Crypto.ECC.PrivateKey?
    }

    func testQueryWithUserPresence() throws {
        let keyTag = "Test Tag \(#function)"
        let privateKey = Crypto.ECC.PrivateKey(curve: .P256)
        let publicKey: Crypto.ECC.PublicKey = privateKey.publicKey()

        let authenticationContext = LAContext()
        var error: NSError?
        guard authenticationContext.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            throw XCTSkip("Device not prepared properly for tests, make sure a passcode is set on the device.")
        }

        try Keychain.saveKey(privateKey, withTag: keyTag, accessControl: .init(itemAccessibility: .afterFirstUnlockThisDeviceOnly, flags: [.userPresence]))
        // Manual confirmation is necessary for this test because we can't know if the user entered the proper password or if the authentication UI did appear properly.
        _ = try Keychain.queryKey(for: publicKey) as Crypto.ECC.PrivateKey?
    }

    func testQueryWithAuthenticationContext() throws {
        continueAfterFailure = false

        let keyTag = "Test Tag \(#function)"
        let privateKey = Crypto.ECC.PrivateKey(curve: .P256)
        let publicKey: Crypto.ECC.PublicKey = privateKey.publicKey()

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

        try Keychain.saveKey(privateKey, withTag: keyTag, accessControl: .init(itemAccessibility: .afterFirstUnlockThisDeviceOnly, flags: [.userPresence]))
        let authentication = Keychain.QueryAuthentication(authenticationContext: authenticationContext, userInterface: .disallow)
        _ = try Keychain.queryKey(for: publicKey, authentication: authentication) as Crypto.ECC.PrivateKey?
    }
}

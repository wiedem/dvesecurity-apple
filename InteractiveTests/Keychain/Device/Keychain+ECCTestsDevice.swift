// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import LocalAuthentication
import Nimble
import XCTest

final class Keychain_ECCTestsiOSDevice: InteractiveTestCaseDevice {
    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .key)
    }

    func testSaveAndQueryWithApplicationPassword() throws {
        let accessControl = Keychain.AccessControl(
            itemAccessibility: .afterFirstUnlockThisDeviceOnly,
            flags: [.applicationPassword(prompt: "Specify a password for the protected access to the keychain")]
        )

        let privateKey = Crypto.ECC.PrivateKey(curve: .p192)
        let keyTag = "Test Tag \(#function)"

        try Keychain.saveKey(privateKey, withTag: keyTag, accessControl: accessControl)

        // Manual confirmation is necessary for this test because we can't know if the user entered the proper password or if the authentication UI did appear properly.
        let queriedKey: Crypto.ECC.PrivateKey? = try wait(description: "Keychain query", timeout: Self.defaultUIInteractionTimeout) {
            let authentication = Keychain.QueryAuthentication(userInterface: .allow(prompt: "Password for the protected access to the keychain item"))
            Keychain.queryKey(withTag: keyTag, authentication: authentication, completion: $0)
        }
        expect(queriedKey?.x963Representation) == privateKey.x963Representation
    }

    func testImplicitSaveAndQueryWithApplicationPassword() throws {
        let accessControl = Keychain.AccessControl(
            itemAccessibility: .afterFirstUnlockThisDeviceOnly,
            flags: [.applicationPassword(prompt: "Specify a password for the protected access to the keychain")]
        )

        let keyTag = "Test Tag \(#function)"
        let privateKey = try Crypto.ECC.PrivateKey(curve: .p192, inKeychainWithTag: keyTag, accessControl: accessControl)

        // Manual confirmation is necessary for this test because we can't know if the user entered the proper password or if the authentication UI did appear properly.
        let queriedKey: Crypto.ECC.PrivateKey? = try wait(description: "Keychain query", timeout: Self.defaultUIInteractionTimeout) {
            let authentication = Keychain.QueryAuthentication(userInterface: .allow(prompt: "Password for the protected access to the keychain item"))
            Keychain.queryKey(withTag: keyTag, authentication: authentication, completion: $0)
        }
        expect(queriedKey?.x963Representation) == privateKey.x963Representation
    }
}

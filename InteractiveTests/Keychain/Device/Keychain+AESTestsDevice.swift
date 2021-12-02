// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import LocalAuthentication
import Nimble
import XCTest

class Keychain_AESTestsDevice: InteractiveTestCaseDevice {
    // swiftlint:disable force_try
    private let key: Crypto.AES.Key = try! Crypto.AES.Key(keySize: Crypto.AES.KeySize.bits256,
                                                          password: "Hello Test!",
                                                          withSalt: "Salt",
                                                          pseudoRandomAlgorithm: .hmacAlgSHA256,
                                                          rounds: 1)

    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .key)
    }

    func testSaveAndQueryWithApplicationPassword() throws {
        let accessControl = Keychain.AccessControl(
            itemAccessibility: .afterFirstUnlockThisDeviceOnly,
            flags: [.applicationPassword(prompt: "Specify a password for the protected access to the keychain")]
        )

        let keyTag = "Test Tag \(#function)"
        let applicationLabel = "appLabel".data(using: .utf8)!

        try Keychain.saveKey(key, withTag: keyTag, applicationLabel: applicationLabel, accessControl: accessControl)

        // Manual confirmation is necessary for this test because we can't know if the user entered the proper password or if the authentication UI did appear properly.
        let queriedKey: Crypto.AES.Key? = try wait(description: "Keychain query", timeout: Self.defaultUIInteractionTimeout) {
            let authentication = Keychain.QueryAuthentication(userInterface: .allow(prompt: "Password for the protected access to the keychain item"))
            Keychain.queryKey(withTag: keyTag, applicationLabel: applicationLabel, authentication: authentication, completion: $0)
        }
        expect(queriedKey) == key
    }
}

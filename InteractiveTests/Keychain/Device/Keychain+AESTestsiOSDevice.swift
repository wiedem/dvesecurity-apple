// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import LocalAuthentication
import Nimble
import XCTest

class Keychain_AESTestsiOSDevice: InteractiveTestCaseDevice {
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
        var queryResult: Result<Crypto.AES.Key?, Error>?

        let result = wait(expectationDescription: "Keychain query", timeout: Self.defaultUIInteractionTimeout) { expectation in
            let authentication = Keychain.QueryAuthentication(userInterface: .allow(prompt: "Password for the protected access to the keychain item"))
            Keychain.queryKey(withTag: keyTag, applicationLabel: applicationLabel, authentication: authentication) { (result: Result<Crypto.AES.Key?, Error>) in
                defer { expectation?.fulfill() }
                queryResult = result
            }
        }
        guard result.isCompleted else { return }

        switch queryResult {
        case let .success(queriedKey):
            expect(queriedKey) == key
        case let .failure(error):
            fail("Failed to query key: \(error)")
        default:
            break
        }
    }
}

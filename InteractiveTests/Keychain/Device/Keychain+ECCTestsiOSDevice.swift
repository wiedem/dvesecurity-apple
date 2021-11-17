// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import LocalAuthentication
import Nimble
import XCTest

class Keychain_ECCTestsiOSDevice: InteractiveTestCaseDevice {
    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .key)
    }

    func testSaveAndQueryWithApplicationPassword() throws {
        let accessControl = Keychain.AccessControl(
            itemAccessibility: .afterFirstUnlockThisDeviceOnly,
            flags: [.applicationPassword(prompt: "Specify a password for the protected access to the keychain")]
        )

        let privateKey = Crypto.ECC.PrivateKey(curve: .P192)
        let keyTag = "Test Tag \(#function)"

        try Keychain.saveKey(privateKey, withTag: keyTag, accessControl: accessControl)

        // Manual confirmation is necessary for this test because we can't know if the user entered the proper password or if the authentication UI did appear properly.
        var queryResult: Result<Crypto.ECC.PrivateKey?, Error>?

        let result = wait(expectationDescription: "Keychain query", timeout: Self.defaultUIInteractionTimeout) { expectation in
            let authentication = Keychain.QueryAuthentication(userInterface: .allow(prompt: "Password for the protected access to the keychain item"))
            Keychain.queryKey(withTag: keyTag, authentication: authentication) { (result: Result<Crypto.ECC.PrivateKey?, Error>) in
                defer { expectation?.fulfill() }
                queryResult = result
            }
        }
        guard result.isCompleted else { return }

        switch queryResult {
        case let .success(queriedKey):
            expect(queriedKey?.x963Representation) == privateKey.x963Representation
        case let .failure(error):
            fail("Failed to query key: \(error)")
        default:
            break
        }
    }

    func testImplicitSaveAndQueryWithApplicationPassword() throws {
        let accessControl = Keychain.AccessControl(
            itemAccessibility: .afterFirstUnlockThisDeviceOnly,
            flags: [.applicationPassword(prompt: "Specify a password for the protected access to the keychain")]
        )

        let keyTag = "Test Tag \(#function)"
        let privateKey = try Crypto.ECC.PrivateKey(curve: .P192, inKeychainWithTag: keyTag, accessControl: accessControl)

        // Manual confirmation is necessary for this test because we can't know if the user entered the proper password or if the authentication UI did appear properly.
        var queryResult: Result<Crypto.ECC.PrivateKey?, Error>?

        let result = wait(expectationDescription: "Keychain query", timeout: Self.defaultUIInteractionTimeout) { expectation in
            let authentication = Keychain.QueryAuthentication(userInterface: .allow(prompt: "Password for the protected access to the keychain item"))
            Keychain.queryKey(withTag: keyTag, authentication: authentication) { (result: Result<Crypto.ECC.PrivateKey?, Error>) in
                defer { expectation?.fulfill() }
                queryResult = result
            }
        }
        guard result.isCompleted else { return }

        switch queryResult {
        case let .success(queriedKey):
            expect(queriedKey?.x963Representation) == privateKey.x963Representation
        case let .failure(error):
            fail("Failed to query key: \(error)")
        default:
            break
        }
    }
}

// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import XCTest

class Keychain_SecureEnclaveTests: TestCaseDevice {
    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .key)
    }

    func testSaveKey() throws {
        let keyTag = "Test Tag \(#function)"

        let key = try Crypto.ECC.SecureEnclaveKey()

        try Keychain.saveKey(key, withTag: keyTag)
        let queriedKey: Crypto.ECC.SecureEnclaveKey? = try wait(description: "Keychain query") {
            Keychain.queryKey(withTag: keyTag, completion: $0)
        }
        expect(queriedKey).toNot(beNil())
    }

    func testQueryECCPrivateKeyAsSecureEnclaveKey() throws {
        let keyTag = "Test Tag \(#function)"

        _ = try Crypto.ECC.PrivateKey(curve: .P256, inKeychainWithTag: keyTag)
        let queriedKey: Crypto.ECC.SecureEnclaveKey? = try wait(description: "Keychain query") {
            Keychain.queryKey(withTag: keyTag, completion: $0)
        }
        expect(queriedKey).to(beNil())
    }

    func testQueryRegularECCKeyDoesntReturnSecureEnclaveKey() throws {
        let keyTag = "Test Tag \(#function)"

        _ = try Crypto.ECC.SecureEnclaveKey(inKeychainWithTag: keyTag)

        expect { () -> Void in
            let queriedKey: Crypto.ECC.PrivateKey? = try self.wait(description: "Keychain query") {
                Keychain.queryKey(withTag: keyTag, completion: $0)
            }
            expect(queriedKey).to(beNil())
        }.to(throwError(Crypto.KeyError.invalidSecKey))
    }

    func testDeleteSecureEnclaveKey() throws {
        let keyTag = "Test Tag \(#function)"

        _ = try Crypto.ECC.SecureEnclaveKey(inKeychainWithTag: keyTag)

        let deleted = try Keychain.deleteSecureEnclaveKey(withTag: keyTag)
        expect(deleted) == true

        let queriedKey: Crypto.ECC.SecureEnclaveKey? = try wait(description: "Keychain query") {
            Keychain.queryKey(withTag: keyTag, completion: $0)
        }
        expect(queriedKey).to(beNil())
    }
}

// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import CryptoKit
import LocalAuthentication
import Nimble
import XCTest

@available(iOS 13.0, *)
final class Keychain_SecureEnclaveTestsiOS13: TestCaseiOS13Device {
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

    func testQuerySecureEnclavePrivateKey() throws {
        let keyTag = "Test Tag \(#function)"

        let key = try Crypto.ECC.SecureEnclaveKey(inKeychainWithTag: keyTag)
        let queriedKey1: Crypto.ECC.SecureEnclaveKey? = try Keychain.queryKey(withTag: keyTag)
        expect(queriedKey1).toNot(beNil())

        let publicKey: Crypto.ECC.PublicKey = key.publicKey()
        let publicKeySha1Data = Hashing.Insecure.SHA1.hash(publicKey.x963Representation)
        let queriedKey2: Crypto.ECC.SecureEnclaveKey? = try Keychain.queryKey(withPublicKeySHA1: publicKeySha1Data)
        expect(queriedKey2).toNot(beNil())

        let queriedKey3: Crypto.ECC.SecureEnclaveKey? = try Keychain.queryKey(for: publicKey)
        expect(queriedKey3).toNot(beNil())
    }

    func testQuerySecureEnclavePrivateKeyAsECCPrivateKey() {
        let keyTag = "Test Tag \(#function)"

        expect { () in
            _ = try Crypto.ECC.SecureEnclaveKey(inKeychainWithTag: keyTag)
            let queriedKey: Crypto.ECC.PrivateKey? = try Keychain.queryKey(withTag: keyTag)
            expect(queriedKey).to(beNil())
        }.to(throwError(Crypto.KeyError.invalidSecKey))
    }

    func testQuerySecureEnclaveKeyDoesntReturnRegularECCKey() throws {
        let keyTag = "Test Tag \(#function)"

        _ = try Crypto.ECC.PrivateKey(curve: .P256, inKeychainWithTag: keyTag)

        expect { () in
            let queriedSecureEnclaveKey: Crypto.ECC.SecureEnclaveKey? = try Keychain.queryKey(withTag: keyTag)
            expect(queriedSecureEnclaveKey).to(beNil())
        }.toNot(throwError())
    }
}

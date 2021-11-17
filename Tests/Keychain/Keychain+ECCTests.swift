// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import XCTest

class Keychain_ECCTests: XCTestCase {
    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .key)
    }

    func testQueryWithoutResult() throws {
        let keyTag = "Test Tag \(#function)"

        let queriedKey: Crypto.ECC.PrivateKey? = try wait(description: "Keychain query") {
            Keychain.queryKey(withTag: keyTag, completion: $0)
        }
        expect(queriedKey).to(beNil())
    }

    func testSaveAndQuery() throws {
        let privateKey = Crypto.ECC.PrivateKey(curve: .P256)
        let publicKey = privateKey.publicKey()
        let keyTag = "Test Tag \(#function)"

        try Keychain.saveKey(privateKey, withTag: keyTag)

        let queriedKey: Crypto.ECC.PrivateKey? = try wait(description: "Keychain query") {
            Keychain.queryKey(for: publicKey, completion: $0)
        }
        expect(queriedKey?.x963Representation) == privateKey.x963Representation
    }

    func testSaveMultipleTimesWithDifferentTags() throws {
        let privateKey = Crypto.ECC.PrivateKey(curve: .P256)
        let publicKey = privateKey.publicKey()
        let keyTag1 = "Test Tag 1 \(#function)"
        let keyTag2 = "Test Tag 2 \(#function)"

        expect {
            try Keychain.saveKey(privateKey, withTag: keyTag1)
            try Keychain.saveKey(privateKey, withTag: keyTag2)
        }.toNot(throwError())

        // Query the key with the first key tag which is supposed to succeed.
        let queriedKey1: Crypto.ECC.PrivateKey? = try wait(description: "Keychain query") {
            Keychain.queryKey(for: publicKey, withTag: keyTag1, completion: $0)
        }

        // Query the key with the second key tag which is supposed to succeed.
        let queriedKey2: Crypto.ECC.PrivateKey? = try wait(description: "Keychain query") {
            Keychain.queryKey(for: publicKey, withTag: keyTag2, completion: $0)
        }

        expect(queriedKey1?.x963Representation) == privateKey.x963Representation
        expect(queriedKey2?.x963Representation) == privateKey.x963Representation

        // Query the key without a tag which is supposed to fail.
        expect {
            let _: Crypto.ECC.PrivateKey? = try self.wait(description: "Keychain query") {
                Keychain.queryKey(for: publicKey, completion: $0)
            }
        }.to(throwError(KeychainError.ambiguousQueryResult))
    }

    func testKeyDeletion() throws {
        let privateKey = Crypto.ECC.PrivateKey(curve: .P256)
        let keyTag = "Test Tag \(#function)"

        try Keychain.saveKey(privateKey, withTag: keyTag)
        let result1 = try Keychain.deletePrivateKey(for: privateKey.publicKey(), withTag: keyTag)
        expect(result1) == true

        try Keychain.saveKey(privateKey, withTag: keyTag)
        let result2 = try Keychain.deleteKey(privateKey, withTag: keyTag)
        expect(result2) == true

        try Keychain.saveKey(privateKey, withTag: keyTag)
        let result3 = try Keychain.deleteKey(ofType: Crypto.ECC.PrivateKey.self, withTag: keyTag)
        expect(result3) == true

        let result4 = try Keychain.deleteKey(privateKey, withTag: keyTag)
        expect(result4) == false
    }
}

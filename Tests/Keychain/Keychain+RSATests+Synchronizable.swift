// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import XCTest

class Keychain_RSA_SynchronizableTests: XCTestCase {
    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .key)
    }

    func testSaveAndQuery() throws {
        let privateKey = try Crypto.RSA.PrivateKey(bitCount: 2048)
        let privateSynchronizedKey = try Crypto.RSA.PrivateKey(bitCount: 2048)
        let keyTag = "Test Tag \(#function)"

        try Keychain.saveKey(privateKey, withTag: keyTag)
        try Keychain.saveSynchronizableKey(privateSynchronizedKey, withTag: keyTag)

        let queriedKey = try queryKey(synchronizable: false, keyTag: keyTag)
        let queriedSynchronizableKey = try queryKey(synchronizable: true, keyTag: keyTag)

        expect(queriedKey?.pkcs1Representation) == privateKey.pkcs1Representation
        expect(queriedSynchronizableKey?.pkcs1Representation) == privateSynchronizedKey.pkcs1Representation
    }

    func testSavingWithEqualAttributesTwice() throws {
        let privateKey = try Crypto.RSA.PrivateKey(bitCount: 2048)
        let keyTag = "Test Tag \(#function)"

        try Keychain.saveSynchronizableKey(privateKey, withTag: keyTag)
        expect {
            try Keychain.saveSynchronizableKey(privateKey, withTag: keyTag)
        }.to(throwError {
            expect($0) == KeychainError.itemSavingFailed(status: errSecDuplicateItem)
        })
    }

    func testDeletion() throws {
        let privateKey = try Crypto.RSA.PrivateKey(bitCount: 2048)
        let keyTag = "Test Tag \(#function)"

        try Keychain.saveSynchronizableKey(privateKey, withTag: keyTag)

        let result1 = try Keychain.deleteSynchronizableKey(privateKey, withTag: keyTag)
        expect(result1) == true
        let result2 = try Keychain.deleteSynchronizableKey(privateKey, withTag: keyTag)
        expect(result2) == false
    }

    func testDeletionWithSyncedUnsynced() throws {
        let privateKey = try Crypto.RSA.PrivateKey(bitCount: 2048)
        let keyTag = "Test Tag \(#function)"
        try Keychain.saveKey(privateKey, withTag: keyTag)
        try Keychain.saveSynchronizableKey(privateKey, withTag: keyTag)

        var queriedKey = try queryKey(synchronizable: false, keyTag: keyTag)
        var queriedSynchronizableKey = try queryKey(synchronizable: true, keyTag: keyTag)
        expect(queriedKey?.pkcs1Representation) == privateKey.pkcs1Representation
        expect(queriedSynchronizableKey?.pkcs1Representation) == privateKey.pkcs1Representation

        try Keychain.deleteKey(ofType: Crypto.RSA.PrivateKey.self, withTag: keyTag)

        queriedKey = try queryKey(synchronizable: false, keyTag: keyTag)
        queriedSynchronizableKey = try queryKey(synchronizable: true, keyTag: keyTag)
        expect(queriedKey).to(beNil())
        expect(queriedSynchronizableKey?.pkcs1Representation) == privateKey.pkcs1Representation

        try Keychain.deleteSynchronizableKey(ofType: Crypto.RSA.PrivateKey.self, withTag: keyTag)

        queriedKey = try queryKey(synchronizable: false, keyTag: keyTag)
        queriedSynchronizableKey = try queryKey(synchronizable: true, keyTag: keyTag)
        expect(queriedKey).to(beNil())
        expect(queriedSynchronizableKey?.pkcs1Representation).to(beNil())
    }
}

// MARK: - Private
private extension Keychain_RSA_SynchronizableTests {
    func queryKey(synchronizable: Bool, keyTag: String, expectationDescription: String = "Keychain query") throws -> Crypto.RSA.PrivateKey? {
        try wait(description: expectationDescription) {
            if synchronizable {
                return Keychain.querySynchronizableKey(withTag: keyTag, completion: $0)
            } else {
                return Keychain.queryKey(withTag: keyTag, completion: $0)
            }
        }
    }
}

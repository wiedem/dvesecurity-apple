// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import XCTest

final class Keychain_ECC_SynchronizableTests: XCTestCase {
    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .key)
    }

    func testSaveAndQuery() throws {
        let privateKey = Crypto.ECC.PrivateKey(curve: .P256)
        let keyTag = "Test Tag \(#function)"

        try Keychain.saveKey(privateKey, withTag: keyTag)
        try Keychain.saveSynchronizableKey(privateKey, withTag: keyTag)

        let queriedKey = try queryKey(synchronizable: false, keyTag: keyTag)
        let queriedSynchronizedKey = try queryKey(synchronizable: true, keyTag: keyTag)
        expect(queriedKey?.x963Representation) == queriedKey?.x963Representation
        expect(queriedSynchronizedKey?.x963Representation) == queriedKey?.x963Representation
    }

    func testSavingWithEqualAttributesTwice() throws {
        let privateKey = Crypto.ECC.PrivateKey(curve: .P256)
        let keyTag = "Test Tag \(#function)"

        try Keychain.saveSynchronizableKey(privateKey, withTag: keyTag)
        expect {
            try Keychain.saveSynchronizableKey(privateKey, withTag: keyTag)
        }.to(throwError {
            expect($0) == KeychainError.itemSavingFailed(status: errSecDuplicateItem)
        })
    }

    func testDeletion() throws {
        let privateKey = Crypto.ECC.PrivateKey(curve: .P256)
        let keyTag = "Test Tag \(#function)"

        try Keychain.saveSynchronizableKey(privateKey, withTag: keyTag)

        let result1 = try Keychain.deleteSynchronizableKey(privateKey, withTag: keyTag)
        expect(result1) == true
        let result2 = try Keychain.deleteSynchronizableKey(privateKey, withTag: keyTag)
        expect(result2) == false
    }

    func testDeletionWithSyncedUnsynced() throws {
        let privateKey = Crypto.ECC.PrivateKey(curve: .P256)
        let keyTag = "Test Tag \(#function)"
        try Keychain.saveKey(privateKey, withTag: keyTag)
        try Keychain.saveSynchronizableKey(privateKey, withTag: keyTag)

        var queriedKey = try queryKey(synchronizable: false, keyTag: keyTag)
        var queriedSynchronizedKey = try queryKey(synchronizable: true, keyTag: keyTag)
        expect(queriedKey?.x963Representation) == privateKey.x963Representation
        expect(queriedSynchronizedKey?.x963Representation) == privateKey.x963Representation

        try Keychain.deleteKey(ofType: Crypto.ECC.PrivateKey.self, withTag: keyTag)

        queriedKey = try queryKey(synchronizable: false, keyTag: keyTag)
        queriedSynchronizedKey = try queryKey(synchronizable: true, keyTag: keyTag)
        expect(queriedKey?.x963Representation).to(beNil())
        expect(queriedSynchronizedKey?.x963Representation) == privateKey.x963Representation

        try Keychain.deleteSynchronizableKey(ofType: Crypto.ECC.PrivateKey.self, withTag: keyTag)

        queriedKey = try queryKey(synchronizable: false, keyTag: keyTag)
        queriedSynchronizedKey = try queryKey(synchronizable: true, keyTag: keyTag)
        expect(queriedKey).to(beNil())
        expect(queriedSynchronizedKey).to(beNil())
    }
}

// MARK: - Private
private extension Keychain_ECC_SynchronizableTests {
    func queryKey(synchronizable: Bool, keyTag: String, expectationDescription: String = "Keychain query") throws -> Crypto.ECC.PrivateKey? {
        try wait(description: expectationDescription) {
            if synchronizable {
                return Keychain.querySynchronizableKey(withTag: keyTag, completion: $0)
            } else {
                return Keychain.queryKey(withTag: keyTag, completion: $0)
            }
        }
    }
}

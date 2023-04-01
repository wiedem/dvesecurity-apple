// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import XCTest

final class Keychain_AES_SynchronizableTests: XCTestCase {
    private static let configuredAccessGroups = Keychain.accessGroups

    // swiftlint:disable force_try
    private let key: Crypto.AES.Key = try! Crypto.AES.Key(keySize: Crypto.AES.KeySize.bits256,
                                                          password: "Hello Test!",
                                                          withSalt: "Salt",
                                                          pseudoRandomAlgorithm: .hmacAlgSHA256,
                                                          rounds: 1)
    private let synchronizedKey: Crypto.AES.Key = try! Crypto.AES.Key(keySize: Crypto.AES.KeySize.bits256,
                                                                      password: "Synchronized Hello Test!",
                                                                      withSalt: "Synchronized Salt",
                                                                      pseudoRandomAlgorithm: .hmacAlgSHA256,
                                                                      rounds: 1)
    private let key2: Crypto.AES.Key = try! Crypto.AES.Key(keySize: Crypto.AES.KeySize.bits256,
                                                           password: "Hello Test!2",
                                                           withSalt: "Salt2",
                                                           pseudoRandomAlgorithm: .hmacAlgSHA256,
                                                           rounds: 1)
    private let synchronizedKey2: Crypto.AES.Key = try! Crypto.AES.Key(keySize: Crypto.AES.KeySize.bits256,
                                                                       password: "Synchronized Hello Test!2",
                                                                       withSalt: "Synchronized Salt2",
                                                                       pseudoRandomAlgorithm: .hmacAlgSHA256,
                                                                       rounds: 1)
    // swiftlint:enable force_try

    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .key, inAccessGroups: Self.configuredAccessGroups)
    }

    func testSaveAndQuery() throws {
        let keyTag = "Test Tag \(#function)"
        let applicationLabel = "appLabel".data(using: .utf8)!

        try Keychain.saveKey(key, withTag: keyTag, applicationLabel: applicationLabel)
        try Keychain.saveSynchronizableKey(synchronizedKey, withTag: keyTag, applicationLabel: applicationLabel)

        let queriedKey = try queryKey(synchronizable: false, keyTag: keyTag, applicationLabel: applicationLabel)
        let queriedSynchronizedKey = try queryKey(synchronizable: true, keyTag: keyTag, applicationLabel: applicationLabel)

        expect(queriedKey) == key
        expect(queriedSynchronizedKey) == synchronizedKey
    }

    func testSaveWithEqualAttributesTwice() throws {
        let keyTag = "Test Tag \(#function)"
        let applicationLabel1 = "appLabel1".data(using: .utf8)

        try Keychain.saveSynchronizableKey(key, withTag: keyTag, applicationLabel: applicationLabel1)
        expect {
            try Keychain.saveSynchronizableKey(self.key2, withTag: keyTag, applicationLabel: applicationLabel1)
        }.to(throwError {
            expect($0) == KeychainError.itemSavingFailed(status: errSecDuplicateItem)
        })
    }

    func testSavingUnconfiguredAccessGroup() {
        let keyTag = "Test Tag \(#function)"
        let applicationLabel = "Test ApplicationLabel \(#function)".data(using: .utf8)

        expect {
            try Keychain.saveSynchronizableKey(self.key, withTag: keyTag, applicationLabel: applicationLabel, accessGroup: "UnknownAccessGroup")
        }.to(throwError {
            expect($0) == KeychainError.itemSavingFailed(status: errSecMissingEntitlement)
        })
    }

    func testUpdateToDifferentAccessGroup() throws {
        let keyTag = "Test Tag \(#function)"
        let applicationLabel = "Test ApplicationLabel \(#function)".data(using: .utf8)

        try Keychain.saveSynchronizableKey(key, withTag: keyTag, applicationLabel: applicationLabel)

        expect {
            try Keychain.updateSynchronizableKey(newKey: self.key2, withTag: keyTag, applicationLabel: applicationLabel, accessGroup: Self.configuredAccessGroups[1])
        }.to(throwError {
            expect($0) == KeychainError.itemUpdateFailed(status: errSecItemNotFound)
        })
    }

    func testUpdate() throws {
        let keyTag = "Test Tag \(#function)"
        let applicationLabel = "appLabel".data(using: .utf8)!
        try Keychain.saveKey(key, withTag: keyTag, applicationLabel: applicationLabel)
        try Keychain.saveSynchronizableKey(synchronizedKey, withTag: keyTag, applicationLabel: applicationLabel)

        try Keychain.updateSynchronizableKey(newKey: synchronizedKey2, withTag: keyTag, applicationLabel: applicationLabel)

        let queriedKey = try queryKey(synchronizable: false, keyTag: keyTag, applicationLabel: applicationLabel)
        let queriedSynchronizedKey = try queryKey(synchronizable: true, keyTag: keyTag, applicationLabel: applicationLabel)
        expect(queriedKey) == key
        expect(queriedSynchronizedKey) == synchronizedKey2
    }

    func testDeletion() throws {
        let keyTag = "Test Tag \(#function)"
        let applicationLabel = "Test ApplicationLabel \(#function)".data(using: .utf8)

        try Keychain.saveSynchronizableKey(key, withTag: keyTag, applicationLabel: applicationLabel)

        let result1 = try Keychain.deleteSynchronizableKey(withTag: keyTag, applicationLabel: applicationLabel)
        expect(result1) == true

        let result2 = try Keychain.deleteSynchronizableKey(withTag: keyTag, applicationLabel: applicationLabel)
        expect(result2) == false
    }

    func testDeletionWithSyncedAndUnsynced() throws {
        let keyTag = "Test Tag \(#function)"
        let applicationLabel = "appLabel".data(using: .utf8)!
        try Keychain.saveKey(key, withTag: keyTag, applicationLabel: applicationLabel)
        try Keychain.saveSynchronizableKey(synchronizedKey, withTag: keyTag, applicationLabel: applicationLabel)

        // Delete unsynced key and query both
        try Keychain.deleteKey(withTag: keyTag, applicationLabel: applicationLabel)

        var queriedKey = try queryKey(synchronizable: false, keyTag: keyTag, applicationLabel: applicationLabel)
        var queriedSynchronizedKey = try queryKey(synchronizable: true, keyTag: keyTag, applicationLabel: applicationLabel)
        expect(queriedKey).to(beNil())
        expect(queriedSynchronizedKey) == synchronizedKey

        // Delete synced key and query both
        try Keychain.deleteSynchronizableKey(withTag: keyTag, applicationLabel: applicationLabel)

        queriedKey = try queryKey(synchronizable: false, keyTag: keyTag, applicationLabel: applicationLabel)
        queriedSynchronizedKey = try queryKey(synchronizable: true, keyTag: keyTag, applicationLabel: applicationLabel)
        expect(queriedKey).to(beNil())
        expect(queriedSynchronizedKey).to(beNil())
    }
}

// MARK: - Private
private extension Keychain_AES_SynchronizableTests {
    func queryKey(synchronizable: Bool, keyTag: String, applicationLabel: Data?, expectationDescription: String = "Keychain query") throws -> Crypto.AES.Key? {
        try wait(description: expectationDescription) {
            if synchronizable {
                return Keychain.querySynchronizableKey(withTag: keyTag, applicationLabel: applicationLabel, completion: $0)
            } else {
                return Keychain.queryKey(withTag: keyTag, applicationLabel: applicationLabel, completion: $0)
            }
        }
    }
}

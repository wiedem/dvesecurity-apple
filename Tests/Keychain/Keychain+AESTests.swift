// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import XCTest

final class Keychain_AESTests: XCTestCase {
    private static let configuredAccessGroups = Keychain.accessGroups

    // swiftlint:disable force_try
    private let key = try! Crypto.AES.Key(keySize: Crypto.AES.KeySize.bits256,
                                          password: "Hello Test!",
                                          withSalt: "Salt",
                                          pseudoRandomAlgorithm: .hmacAlgSHA256,
                                          rounds: 1)
    private let key2 = try! Crypto.AES.Key(keySize: Crypto.AES.KeySize.bits256,
                                           password: "Hello Test!2",
                                           withSalt: "Salt2",
                                           pseudoRandomAlgorithm: .hmacAlgSHA256,
                                           rounds: 1)
    // swiftlint:enable force_try

    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .key, inAccessGroups: Self.configuredAccessGroups)
    }

    func testQueryWithoutResult() throws {
        let keyTag = "Test Tag \(#function)"
        let applicationLabel = "appLabel".data(using: .utf8)!

        let queriedKey: Crypto.AES.Key? = try wait(description: "Keychain query") {
            Keychain.queryKey(withTag: keyTag, applicationLabel: applicationLabel, completion: $0)
        }
        expect(queriedKey).to(beNil())
    }

    func testSaveAndQuery() throws {
        let keyTag = "Test Tag \(#function)"
        let applicationLabel = "appLabel".data(using: .utf8)!

        try Keychain.saveKey(key, withTag: keyTag, applicationLabel: applicationLabel)

        let queriedKey: Crypto.AES.Key? = try wait(description: "Keychain query") {
            Keychain.queryKey(withTag: keyTag, applicationLabel: applicationLabel, completion: $0)
        }
        expect(queriedKey) == key
    }

    func testSaveWithEqualAttributesTwice() throws {
        let keyTag = "Test Tag \(#function)"
        let applicationLabel1 = "appLabel1".data(using: .utf8)

        try Keychain.saveKey(key, withTag: keyTag, applicationLabel: applicationLabel1)
        expect {
            try Keychain.saveKey(self.key2, withTag: keyTag, applicationLabel: applicationLabel1)
        }.to(throwError {
            expect($0) == KeychainError.itemSavingFailed(status: errSecDuplicateItem)
        })
    }

    func testSavingUnconfiguredAccessGroup() {
        let keyTag = "Test Tag \(#function)"
        let applicationLabel = "Test ApplicationLabel \(#function)".data(using: .utf8)

        expect {
            try Keychain.saveKey(self.key, withTag: keyTag, applicationLabel: applicationLabel, accessGroup: "UnknownAccessGroup")
        }.to(throwError {
            expect($0) == KeychainError.itemSavingFailed(status: errSecMissingEntitlement)
        })
    }

    func testUpdateToDifferentAccessGroup() throws {
        let keyTag = "Test Tag \(#function)"
        let applicationLabel = "Test ApplicationLabel \(#function)".data(using: .utf8)

        try Keychain.saveKey(key, withTag: keyTag, applicationLabel: applicationLabel)

        expect {
            try Keychain.updateKey(newKey: self.key2, withTag: keyTag, applicationLabel: applicationLabel, accessGroup: Self.configuredAccessGroups[1])
        }.to(throwError {
            expect($0) == KeychainError.itemUpdateFailed(status: errSecItemNotFound)
        })
    }

    func testDeletion() throws {
        let keyTag = "Test Tag \(#function)"
        let applicationLabel = "Test ApplicationLabel \(#function)".data(using: .utf8)

        try Keychain.saveKey(key, withTag: keyTag, applicationLabel: applicationLabel)

        let result1 = try Keychain.deleteKey(withTag: keyTag, applicationLabel: applicationLabel)
        expect(result1) == true

        let result2 = try Keychain.deleteKey(withTag: keyTag, applicationLabel: applicationLabel)
        expect(result2) == false
    }
}

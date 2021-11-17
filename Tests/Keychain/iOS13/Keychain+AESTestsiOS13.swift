// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import LocalAuthentication
import Nimble
import XCTest

@available(iOS 13.0, *)
class Keychain_AESTestsiOS13: TestCaseiOS13 {
    private static let configuredAccessGroups = Keychain.accessGroups

    // swiftlint:disable force_try
    private let key: Crypto.AES.Key = try! Crypto.AES.Key(keySize: Crypto.AES.KeySize.bits256,
                                                          password: "Hello Test!",
                                                          withSalt: "Salt",
                                                          pseudoRandomAlgorithm: .hmacAlgSHA256,
                                                          rounds: 1)
    private let key2: Crypto.AES.Key = try! Crypto.AES.Key(keySize: Crypto.AES.KeySize.bits256,
                                                           password: "Hello Test!2",
                                                           withSalt: "Salt2",
                                                           pseudoRandomAlgorithm: .hmacAlgSHA256,
                                                           rounds: 1)

    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .key, inAccessGroups: Self.configuredAccessGroups)
    }

    func testSaveAndQueryAESKey() throws {
        let keyTag = "Test Tag \(#function)"

        try Keychain.saveKey(key, withTag: keyTag, applicationLabel: nil)

        let fetchedKey: Crypto.AES.Key? = try Keychain.queryKey(withTag: keyTag, applicationLabel: nil)

        expect(fetchedKey).toNot(beNil())
        expect(fetchedKey) == key
    }

    func testUpdate() throws {
        let keyTag = "Test Tag \(#function)"
        try Keychain.saveKey(key, withTag: keyTag, applicationLabel: nil)

        let fetchedKey: Crypto.AES.Key? = try Keychain.queryKey(withTag: keyTag, applicationLabel: nil)
        expect(fetchedKey) == key

        try Keychain.updateKey(newKey: key2, withTag: keyTag, applicationLabel: nil)

        let fetchedKeyAfterUpdate: Crypto.AES.Key? = try Keychain.queryKey(withTag: keyTag, applicationLabel: nil)
        expect(fetchedKeyAfterUpdate) == key2
    }

    func testSaveWithDifferentTags() throws {
        let keyTag = "Test Tag \(#function)"
        let keyTag2 = "Test Tag2 \(#function)"

        try Keychain.saveKey(key, withTag: keyTag, applicationLabel: nil)
        try Keychain.saveKey(key2, withTag: keyTag2, applicationLabel: nil)

        let fetchedKey: Crypto.AES.Key? = try Keychain.queryKey(withTag: keyTag, applicationLabel: nil)
        let fetchedKey2: Crypto.AES.Key? = try Keychain.queryKey(withTag: keyTag2, applicationLabel: nil)
        expect(fetchedKey) == key
        expect(fetchedKey2) == key2
    }

    func testSaveAESKeyWithDifferentApplicationLabel() throws {
        let keyTag = "Test Tag \(#function)"
        let applicationLabel1 = "appLabel1".data(using: .utf8)
        let applicationLabel2 = "appLabel2".data(using: .utf8)

        try Keychain.saveKey(key, withTag: keyTag, applicationLabel: applicationLabel1)
        try Keychain.saveKey(key2, withTag: keyTag, applicationLabel: applicationLabel2)

        let fetchedKey1: Crypto.AES.Key? = try Keychain.queryKey(withTag: keyTag, applicationLabel: applicationLabel1)
        let fetchedKey2: Crypto.AES.Key? = try Keychain.queryKey(withTag: keyTag, applicationLabel: applicationLabel2)

        expect(fetchedKey1) == key
        expect(fetchedKey2) == key2
    }

    func testDeletionWithoutSpecifyingApplicationLabel() throws {
        let keyTag = "Test Tag \(#function)"
        let applicationLabel1 = "appLabel1".data(using: .utf8)
        let applicationLabel2 = "appLabel2".data(using: .utf8)

        try Keychain.saveKey(key, withTag: keyTag, applicationLabel: applicationLabel1)
        try Keychain.saveKey(key2, withTag: keyTag, applicationLabel: applicationLabel2)

        let fetchedKey1: Crypto.AES.Key? = try Keychain.queryKey(withTag: keyTag, applicationLabel: applicationLabel1)
        let fetchedKey2: Crypto.AES.Key? = try Keychain.queryKey(withTag: keyTag, applicationLabel: applicationLabel2)
        expect(fetchedKey1) == key
        expect(fetchedKey2) == key2

        try Keychain.deleteKey(withTag: keyTag, applicationLabel: nil)

        let fetchedKey1AfterDeletion: Crypto.AES.Key? = try Keychain.queryKey(withTag: keyTag, applicationLabel: applicationLabel1)
        let fetchedKey2AfterDeletion: Crypto.AES.Key? = try Keychain.queryKey(withTag: keyTag, applicationLabel: applicationLabel2)
        expect(fetchedKey1AfterDeletion).to(beNil())
        expect(fetchedKey2AfterDeletion).to(beNil())
    }

    func testSaveDifferentAccessGroups() throws {
        let keyTag = "Test Tag \(#function)"
        let applicationLabel = "Test ApplicationLabel \(#function)".data(using: .utf8)

        try Keychain.saveKey(key, withTag: keyTag, applicationLabel: applicationLabel, accessGroup: Self.configuredAccessGroups[0])
        try Keychain.saveKey(key2, withTag: keyTag, applicationLabel: applicationLabel, accessGroup: Self.configuredAccessGroups[1])

        let fetchedKey1: Crypto.AES.Key? = try Keychain.queryKey(withTag: keyTag, applicationLabel: applicationLabel, accessGroup: Self.configuredAccessGroups[0])
        let fetchedKey2: Crypto.AES.Key? = try Keychain.queryKey(withTag: keyTag, applicationLabel: applicationLabel, accessGroup: Self.configuredAccessGroups[1])
        expect(fetchedKey1) == key
        expect(fetchedKey2) == key2
    }
}

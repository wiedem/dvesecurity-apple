// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import LocalAuthentication
import Nimble
import XCTest

@available(iOS 13.0, *)
final class Keychain_RSATestsiOS13: TestCaseiOS13 {
    private static let keychainAccessGroups = Keychain.accessGroups

    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .key)
    }

    func testQueryRSAPrivateKey() throws {
        let privateKey = try Crypto.RSA.PrivateKey(bitCount: 2048)
        let publicKey = privateKey.publicKey()
        let keyTag = "Test Tag \(#function)"

        try Keychain.saveKey(privateKey, withTag: keyTag)

        let fetchedPrivateKey1: Crypto.RSA.PrivateKey? = try Keychain.queryKey(for: publicKey)
        let publicKeySHA1 = Hashing.Insecure.SHA1.hash(publicKey.pkcs1Representation)
        let fetchedPrivateKey2: Crypto.RSA.PrivateKey? = try Keychain.queryKey(withPublicKeySHA1: publicKeySHA1)
        let fetchedPrivateKey3: Crypto.RSA.PrivateKey? = try Keychain.queryKey(withTag: keyTag)

        expect(fetchedPrivateKey1).toNot(beNil())
        expect(fetchedPrivateKey2).toNot(beNil())
        expect(fetchedPrivateKey3).toNot(beNil())
        expect(fetchedPrivateKey1?.pkcs1Representation) == fetchedPrivateKey1?.pkcs1Representation
        expect(fetchedPrivateKey1?.pkcs1Representation) == fetchedPrivateKey3?.pkcs1Representation
    }

    func testImplicitlySavedRSAPrivateKey() throws {
        let keyTag = "Test Tag \(#function)"
        let privateKey = try Crypto.RSA.PrivateKey(bitCount: 2048, inKeychainWithTag: keyTag, accessControl: .afterFirstUnlockThisDeviceOnly)

        let publicKey = privateKey.publicKey()
        let fetchedPrivateKey: Crypto.RSA.PrivateKey? = try Keychain.queryKey(for: publicKey)
        expect(fetchedPrivateKey).toNot(beNil())
        expect(fetchedPrivateKey?.pkcs1Representation) == privateKey.pkcs1Representation
    }

    func testSaveRSAPrivateKey() throws {
        let privateKey1 = try Crypto.RSA.PrivateKey(bitCount: 2048)
        let publicKey1 = privateKey1.publicKey()
        let keyTag = "Test Tag \(#function)"

        try Keychain.saveKey(privateKey1, withTag: keyTag)

        //
        let privateKey2 = try Crypto.RSA.PrivateKey(bitCount: 2048)
        let publicKey2 = privateKey2.publicKey()
        try Keychain.saveKey(privateKey2, withTag: keyTag)

        //
        let fetchedPrivateKey1: Crypto.RSA.PrivateKey? = try Keychain.queryKey(for: publicKey1)
        let fetchedPrivateKey2: Crypto.RSA.PrivateKey? = try Keychain.queryKey(for: publicKey2)

        expect(fetchedPrivateKey1).toNot(beNil())
        expect(fetchedPrivateKey2).toNot(beNil())

        if let fetchedPrivateKey1 = fetchedPrivateKey1, let fetchedPrivateKey2 = fetchedPrivateKey2 {
            expect(fetchedPrivateKey1.pkcs1Representation) != fetchedPrivateKey2.pkcs1Representation
        }
    }

    func testSaveRSAPrivateKeyMultipleTimes() throws {
        let privateKey = try Crypto.RSA.PrivateKey(bitCount: 2048)
        let keyTag1 = "Test Tag 1 \(#function)"
        let keyTag2 = "Test Tag 2 \(#function)"

        try Keychain.saveKey(privateKey, withTag: keyTag1)
        try Keychain.saveKey(privateKey, withTag: keyTag2)

        //
        let fetchedPrivateKey1: Crypto.RSA.PrivateKey? = try Keychain.queryKey(withTag: keyTag1)
        let fetchedPrivateKey2: Crypto.RSA.PrivateKey? = try Keychain.queryKey(withTag: keyTag2)

        expect(fetchedPrivateKey1).toNot(beNil())
        expect(fetchedPrivateKey2).toNot(beNil())

        expect(fetchedPrivateKey1?.pkcs1Representation) == privateKey.pkcs1Representation
        expect(fetchedPrivateKey2?.pkcs1Representation) == privateKey.pkcs1Representation

        //
        try Keychain.deleteKey(privateKey, withTag: keyTag1)
        let fetchedPrivateKey3: Crypto.RSA.PrivateKey? = try Keychain.queryKey(withTag: keyTag1)
        let fetchedPrivateKey4: Crypto.RSA.PrivateKey? = try Keychain.queryKey(withTag: keyTag2)

        expect(fetchedPrivateKey3).to(beNil())
        expect(fetchedPrivateKey4).toNot(beNil())

        //
        try Keychain.deleteKey(privateKey, withTag: keyTag2)
        let fetchedPrivateKey5: Crypto.RSA.PrivateKey? = try Keychain.queryKey(withTag: keyTag1)
        let fetchedPrivateKey6: Crypto.RSA.PrivateKey? = try Keychain.queryKey(withTag: keyTag2)

        expect(fetchedPrivateKey5).to(beNil())
        expect(fetchedPrivateKey6).to(beNil())
    }

    func testDeleteRSAPrivateKey() throws {
        let privateKey = try Crypto.RSA.PrivateKey(bitCount: 2048)
        let keyTag = "Test Tag \(#function)"

        try Keychain.saveKey(privateKey, withTag: keyTag)
        try Keychain.deleteKey(privateKey, withTag: keyTag)

        let publicKey = privateKey.publicKey()
        let queriedKey: Crypto.RSA.PrivateKey? = try Keychain.queryKey(for: publicKey)
        expect(queriedKey).to(beNil())
    }

    func testDeleteRSAPrivateKeyForPublicKey() throws {
        let privateKey = try Crypto.RSA.PrivateKey(bitCount: 2048)
        let publicKey = privateKey.publicKey()
        let keyTag = "Test Tag \(#function)"

        try Keychain.saveKey(privateKey, withTag: keyTag)
        try Keychain.deletePrivateKey(for: publicKey, withTag: keyTag)

        let queriedKey: Crypto.RSA.PrivateKey? = try Keychain.queryKey(for: publicKey)
        expect(queriedKey).to(beNil())
    }

    func testRSAPrivateKeyAccessGroup() throws {
        let privateKey = try Crypto.RSA.PrivateKey(bitCount: 2048)
        let publicKey = privateKey.publicKey()
        let keyTag = "Test Tag \(#function)"

        try Keychain.saveKey(privateKey, withTag: keyTag, accessGroup: Self.keychainAccessGroups[0])

        let fetchedPrivateKey1: Crypto.RSA.PrivateKey? = try Keychain.queryKey(for: publicKey)
        let fetchedPrivateKey2: Crypto.RSA.PrivateKey? = try Keychain.queryKey(for: publicKey, accessGroup: Self.keychainAccessGroups[0])
        let fetchedPrivateKey3: Crypto.RSA.PrivateKey? = try Keychain.queryKey(for: publicKey, accessGroup: Self.keychainAccessGroups[1])

        expect(fetchedPrivateKey1?.pkcs1Representation) == privateKey.pkcs1Representation
        expect(fetchedPrivateKey2?.pkcs1Representation) == privateKey.pkcs1Representation
        expect(fetchedPrivateKey3).to(beNil())
    }
}

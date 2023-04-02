// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import LocalAuthentication
import Nimble
import XCTest

@available(iOS 13.0, *)
final class Keychain_ECCTestsiOS13: TestCaseiOS13 {
    private static let keychainAccessGroups = Keychain.accessGroups

    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .key)
    }

    func testQueryECCPrivateKey() throws {
        let privateKey = Crypto.ECC.PrivateKey(curve: .p192)
        let publicKey: Crypto.ECC.PublicKey = privateKey.publicKey()
        let keyTag = "Test Tag \(#function)"

        try Keychain.saveKey(privateKey, withTag: keyTag)

        let fetchedPrivateKey1: Crypto.ECC.PrivateKey? = try Keychain.queryKey(for: publicKey)
        let publicKeySHA1 = Hashing.Insecure.SHA1.hash(publicKey.x963Representation)
        let fetchedPrivateKey2: Crypto.ECC.PrivateKey? = try Keychain.queryKey(withPublicKeySHA1: publicKeySHA1)
        let fetchedPrivateKey3: Crypto.ECC.PrivateKey? = try Keychain.queryKey(withTag: keyTag)

        expect(fetchedPrivateKey1).toNot(beNil())
        expect(fetchedPrivateKey2).toNot(beNil())
        expect(fetchedPrivateKey3).toNot(beNil())
        expect(fetchedPrivateKey1?.x963Representation) == fetchedPrivateKey1?.x963Representation
        expect(fetchedPrivateKey1?.x963Representation) == fetchedPrivateKey3?.x963Representation
    }

    func testImplicitlySavedECCPrivateKey() throws {
        let keyTag = "Test Tag \(#function)"
        let privateKey = try Crypto.ECC.PrivateKey(curve: .p192, inKeychainWithTag: keyTag, accessControl: .whenUnlockedThisDeviceOnly)

        let publicKey: Crypto.ECC.PublicKey = privateKey.publicKey()
        let fetchedPrivateKey: Crypto.ECC.PrivateKey? = try Keychain.queryKey(for: publicKey)
        expect(fetchedPrivateKey).toNot(beNil())
        expect(fetchedPrivateKey?.x963Representation) == privateKey.x963Representation
    }

    func testSaveECCPrivateKey() throws {
        let privateKey1 = Crypto.ECC.PrivateKey(curve: .p192)
        let publicKey1: Crypto.ECC.PublicKey = privateKey1.publicKey()
        let keyTag = "Test Tag \(#function)"

        try Keychain.saveKey(privateKey1, withTag: keyTag)

        //
        let privateKey2 = Crypto.ECC.PrivateKey(curve: .p192)
        let publicKey2: Crypto.ECC.PublicKey = privateKey2.publicKey()
        try Keychain.saveKey(privateKey2, withTag: keyTag)

        //
        let fetchedPrivateKey1: Crypto.ECC.PrivateKey? = try Keychain.queryKey(for: publicKey1)
        let fetchedPrivateKey2: Crypto.ECC.PrivateKey? = try Keychain.queryKey(for: publicKey2)

        expect(fetchedPrivateKey1).toNot(beNil())
        expect(fetchedPrivateKey2).toNot(beNil())

        if let fetchedPrivateKey1, let fetchedPrivateKey2 {
            expect(fetchedPrivateKey1.x963Representation) != fetchedPrivateKey2.x963Representation
        }
    }

    func testSaveECCPrivateKeyMultipleTimes() throws {
        let privateKey = Crypto.ECC.PrivateKey(curve: .p256)
        let keyTag1 = "Test Tag 1 \(#function)"
        let keyTag2 = "Test Tag 2 \(#function)"

        try Keychain.saveKey(privateKey, withTag: keyTag1)
        try Keychain.saveKey(privateKey, withTag: keyTag2)

        //
        let fetchedPrivateKey1: Crypto.ECC.PrivateKey? = try Keychain.queryKey(withTag: keyTag1)
        let fetchedPrivateKey2: Crypto.ECC.PrivateKey? = try Keychain.queryKey(withTag: keyTag2)

        expect(fetchedPrivateKey1).toNot(beNil())
        expect(fetchedPrivateKey2).toNot(beNil())

        expect(fetchedPrivateKey1?.x963Representation) == privateKey.x963Representation
        expect(fetchedPrivateKey2?.x963Representation) == privateKey.x963Representation

        //
        try Keychain.deleteKey(privateKey, withTag: keyTag1)
        let fetchedPrivateKey3: Crypto.ECC.PrivateKey? = try Keychain.queryKey(withTag: keyTag1)
        let fetchedPrivateKey4: Crypto.ECC.PrivateKey? = try Keychain.queryKey(withTag: keyTag2)

        expect(fetchedPrivateKey3).to(beNil())
        expect(fetchedPrivateKey4).toNot(beNil())

        //
        try Keychain.deleteKey(privateKey, withTag: keyTag2)
        let fetchedPrivateKey5: Crypto.ECC.PrivateKey? = try Keychain.queryKey(withTag: keyTag1)
        let fetchedPrivateKey6: Crypto.ECC.PrivateKey? = try Keychain.queryKey(withTag: keyTag2)

        expect(fetchedPrivateKey5).to(beNil())
        expect(fetchedPrivateKey6).to(beNil())
    }

    func testDeleteECCPrivateKey() throws {
        let privateKey = Crypto.ECC.PrivateKey(curve: .p192)
        let keyTag = "Test Tag \(#function)"

        try Keychain.saveKey(privateKey, withTag: keyTag)
        try Keychain.deleteKey(privateKey, withTag: keyTag)

        let publicKey: Crypto.ECC.PublicKey = privateKey.publicKey()
        let queriedKey: Crypto.ECC.PrivateKey? = try Keychain.queryKey(for: publicKey)
        expect(queriedKey).to(beNil())
    }

    func testDeleteECCPrivateKeyForPublicKey() throws {
        let privateKey = Crypto.ECC.PrivateKey(curve: .p192)
        let publicKey: Crypto.ECC.PublicKey = privateKey.publicKey()
        let keyTag = "Test Tag \(#function)"

        try Keychain.saveKey(privateKey, withTag: keyTag)
        try Keychain.deletePrivateKey(for: publicKey, withTag: keyTag)

        let queriedKey: Crypto.ECC.PrivateKey? = try Keychain.queryKey(for: publicKey)
        expect(queriedKey).to(beNil())
    }

    func testECCPrivateKeyAccessGroup() throws {
        let privateKey = Crypto.ECC.PrivateKey(curve: .p192)
        let publicKey: Crypto.ECC.PublicKey = privateKey.publicKey()
        let keyTag = "Test Tag \(#function)"

        try Keychain.saveKey(privateKey, withTag: keyTag, accessGroup: Self.keychainAccessGroups[0])

        let fetchedPrivateKey1: Crypto.ECC.PrivateKey? = try Keychain.queryKey(for: publicKey)
        let fetchedPrivateKey2: Crypto.ECC.PrivateKey? = try Keychain.queryKey(for: publicKey, accessGroup: Self.keychainAccessGroups[0])
        let fetchedPrivateKey3: Crypto.ECC.PrivateKey? = try Keychain.queryKey(for: publicKey, accessGroup: Self.keychainAccessGroups[1])

        expect(fetchedPrivateKey1?.x963Representation) == privateKey.x963Representation
        expect(fetchedPrivateKey2?.x963Representation) == privateKey.x963Representation
        expect(fetchedPrivateKey3).to(beNil())
    }
}

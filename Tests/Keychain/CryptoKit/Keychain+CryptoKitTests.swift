// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
#if canImport(CryptoKit)
import CryptoKit
import Nimble
import XCTest

@available(iOS 13.0, *)
final class Keychain_CryptoKitTests: TestCaseCryptoKit {
    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .key)
        try Keychain.deleteAllItems(ofClass: .genericPassword)
    }

    func testP256SigningPrivateKeyStorage() throws {
        let privateKey = P256.Signing.PrivateKey()
        let keyTag = "Test Tag \(#function)"

        try Keychain.saveKey(privateKey, withTag: keyTag)

        guard let queriedKey: P256.Signing.PrivateKey = try Keychain.queryKey(withTag: keyTag) else {
            fail("Saved CryptoKit private ECC key was not found in keychain.")
            return
        }
        expect(queriedKey.x963Representation) == privateKey.x963Representation

        guard let queriedKey2: P256.Signing.PrivateKey = try Keychain.queryKey(for: privateKey.publicKey) else {
            fail("Saved CryptoKit private ECC key was not found in keychain.")
            return
        }
        expect(queriedKey2.x963Representation) == privateKey.x963Representation
    }

    func testP256KeyAgreementPrivateKeyStorage() throws {
        let privateKey = P256.KeyAgreement.PrivateKey()
        let keyTag = "Test Tag \(#function)"

        try Keychain.saveKey(privateKey, withTag: keyTag)

        guard let queriedKey: P256.KeyAgreement.PrivateKey = try Keychain.queryKey(withTag: keyTag) else {
            fail("Saved CryptoKit private ECC key was not found in keychain.")
            return
        }
        expect(queriedKey.x963Representation) == privateKey.x963Representation

        guard let queriedKey2: P256.KeyAgreement.PrivateKey = try Keychain.queryKey(for: privateKey.publicKey) else {
            fail("Saved CryptoKit private ECC key was not found in keychain.")
            return
        }
        expect(queriedKey2.x963Representation) == privateKey.x963Representation
    }

    func testP384SigningPrivateKeyStorage() throws {
        let privateKey = P384.Signing.PrivateKey()
        let keyTag = "Test Tag \(#function)"

        try Keychain.saveKey(privateKey, withTag: keyTag)

        guard let queriedKey: P384.Signing.PrivateKey = try Keychain.queryKey(withTag: keyTag) else {
            fail("Saved CryptoKit private ECC key was not found in keychain.")
            return
        }
        expect(queriedKey.x963Representation) == privateKey.x963Representation

        guard let queriedKey2: P384.Signing.PrivateKey = try Keychain.queryKey(for: privateKey.publicKey) else {
            fail("Saved CryptoKit private ECC key was not found in keychain.")
            return
        }
        expect(queriedKey2.x963Representation) == privateKey.x963Representation
    }

    func testP384KeyAgreementPrivateKeyStorage() throws {
        let privateKey = P384.KeyAgreement.PrivateKey()
        let keyTag = "Test Tag \(#function)"

        try Keychain.saveKey(privateKey, withTag: keyTag)

        guard let queriedKey: P384.KeyAgreement.PrivateKey = try Keychain.queryKey(withTag: keyTag) else {
            fail("Saved CryptoKit private ECC key was not found in keychain.")
            return
        }
        expect(queriedKey.x963Representation) == privateKey.x963Representation

        guard let queriedKey2: P384.KeyAgreement.PrivateKey = try Keychain.queryKey(for: privateKey.publicKey) else {
            fail("Saved CryptoKit private ECC key was not found in keychain.")
            return
        }
        expect(queriedKey2.x963Representation) == privateKey.x963Representation
    }

    func testP521SigningPrivateKeyStorage() throws {
        let privateKey = P521.Signing.PrivateKey()
        let keyTag = "Test Tag \(#function)"

        try Keychain.saveKey(privateKey, withTag: keyTag)

        guard let queriedKey: P521.Signing.PrivateKey = try Keychain.queryKey(withTag: keyTag) else {
            fail("Saved CryptoKit private ECC key was not found in keychain.")
            return
        }
        expect(queriedKey.x963Representation) == privateKey.x963Representation

        guard let queriedKey2: P521.Signing.PrivateKey = try Keychain.queryKey(for: privateKey.publicKey) else {
            fail("Saved CryptoKit private ECC key was not found in keychain.")
            return
        }
        expect(queriedKey2.x963Representation) == privateKey.x963Representation
    }

    func testP521KeyAgreementPrivateKeyStorage() throws {
        let privateKey = P521.KeyAgreement.PrivateKey()
        let keyTag = "Test Tag \(#function)"

        try Keychain.saveKey(privateKey, withTag: keyTag)

        guard let queriedKey: P521.KeyAgreement.PrivateKey = try Keychain.queryKey(withTag: keyTag) else {
            fail("Saved CryptoKit private ECC key was not found in keychain.")
            return
        }
        expect(queriedKey.x963Representation) == privateKey.x963Representation

        guard let queriedKey2: P521.KeyAgreement.PrivateKey = try Keychain.queryKey(for: privateKey.publicKey) else {
            fail("Saved CryptoKit private ECC key was not found in keychain.")
            return
        }
        expect(queriedKey2.x963Representation) == privateKey.x963Representation
    }

    func testCurve25519PrivateKeyStorage() throws {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let account = "account"
        let service = "service"

        try Keychain.GenericPassword.saveKey(privateKey, forAccount: account, service: service)
        guard let queriedKey: Curve25519.KeyAgreement.PrivateKey = try Keychain.GenericPassword.queryKey(forAccount: account, service: service) else {
            fail("Saved CryptoKit private ECC key was not found in keychain.")
            return
        }
        expect(queriedKey.rawRepresentation) == privateKey.rawRepresentation
    }

    func testSecureEnclaveP256SigningPrivateKeyStorage() throws {
        let privateKey = try SecureEnclave.P256.Signing.PrivateKey()
        let account = "account"
        let service = "service"

        try Keychain.GenericPassword.saveKey(privateKey, forAccount: account, service: service)
        let queriedKey: SecureEnclave.P256.Signing.PrivateKey? = try Keychain.GenericPassword.queryKey(forAccount: account, service: service)
        expect(queriedKey).toNot(beNil())
    }

    func testSecureEnclaveP256KeyAgreementPrivateKeyStorage() throws {
        let privateKey = try SecureEnclave.P256.KeyAgreement.PrivateKey()
        let account = "account"
        let service = "service"

        try Keychain.GenericPassword.saveKey(privateKey, forAccount: account, service: service)
        let queriedKey: SecureEnclave.P256.KeyAgreement.PrivateKey? = try Keychain.GenericPassword.queryKey(forAccount: account, service: service)
        expect(queriedKey).toNot(beNil())
    }

    func testSymmetricKeyStorage() throws {
        let key = CryptoKit.SymmetricKey(size: .bits256)
        let keyTag = "Test Tag \(#function)"

        try Keychain.saveKey(key, withTag: keyTag, applicationLabel: nil)

        guard let queriedKey: CryptoKit.SymmetricKey = try Keychain.queryKey(withTag: keyTag, applicationLabel: nil) else {
            fail("Saved symmetric key was not found in keychain.")
            return
        }
        expect(queriedKey.bitCount) == 256
        expect(key) == queriedKey
    }
}
#endif

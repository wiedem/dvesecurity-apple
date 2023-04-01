// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import XCTest

final class ASN1_CoderTests: XCTestCase {
    func testEncodeRSAPrivateKey() throws {
        let key = try Crypto.RSA.PrivateKey(bitCount: 1024)
        let pkcs1Data = key.pkcs1Representation

        let asn1PrivateKey = try ASN1.RSAPrivateKey(pkcs1Data: pkcs1Data)
        let encodedData = try ASN1.Coder.encode(asn1PrivateKey)

        expect(pkcs1Data) == encodedData
    }

    func testEncodeRSAPublicKey() throws {
        let key = try Crypto.RSA.PrivateKey(bitCount: 1024)
        let pkcs1Data = key.publicKey().pkcs1Representation

        let asn1PublicKey = try ASN1.RSAPublicKey(pkcs1Data: pkcs1Data)
        let encodedData = try ASN1.Coder.encode(asn1PublicKey)

        expect(pkcs1Data) == encodedData
    }

    func testDecodeRSAPrivateKey() throws {
        let key = try Crypto.RSA.PrivateKey(bitCount: 1024)
        let pkcs1Data = key.pkcs1Representation

        let asn1PrivateKey = try ASN1.RSAPrivateKey(pkcs1Data: pkcs1Data)
        let decodedAsn1PrivateKey: ASN1.RSAPrivateKey = try ASN1.Coder.decode(pkcs1Data)

        expect(asn1PrivateKey) == decodedAsn1PrivateKey
    }

    func testDecodeRSAPublicKey() throws {
        let key = try Crypto.RSA.PrivateKey(bitCount: 1024).publicKey()
        let pkcs1Data = key.pkcs1Representation

        let asn1PublicKey = try ASN1.RSAPublicKey(pkcs1Data: pkcs1Data)
        let decodedAsn1PublicKey: ASN1.RSAPublicKey = try ASN1.Coder.decode(pkcs1Data)

        expect(asn1PublicKey) == decodedAsn1PublicKey
    }
}

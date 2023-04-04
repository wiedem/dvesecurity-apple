// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import SwiftASN1
import XCTest

final class ASN1PKCS1Tests: XCTestCase {
    func testRSAPrivateKeyCoding() throws {
        let key = try Crypto.RSA.PrivateKey(bitCount: 1024)
        let pkcs1Data = key.pkcs1Representation

        let asn1PrivateKey = try ASN1.PKCS1.RSAPrivateKey(derData: pkcs1Data)
        let derBytes = try Data(asn1PrivateKey.derBytes())

        expect(pkcs1Data) == derBytes
    }

    func testRSAPublicKeyCoding() throws {
        let key = try Crypto.RSA.PrivateKey(bitCount: 1024)
        let pkcs1Data = key.publicKey().pkcs1Representation

        let asn1PublicKey = try ASN1.PKCS1.RSAPublicKey(derData: pkcs1Data)
        let encodedData = try Data(asn1PublicKey.derBytes())

        expect(pkcs1Data) == encodedData
    }
}

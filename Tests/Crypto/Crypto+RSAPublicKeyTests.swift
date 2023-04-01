// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import XCTest

final class RSAPublicKeyTests: XCTestCase {
    private lazy var x509TestFileURL = Bundle.main.url(forResource: "X509RSAPublicKey", withExtension: "der")!

    func testCreationFromX509() throws {
        let x509Data = try Data(contentsOf: x509TestFileURL)
        _ = try Crypto.RSA.PublicKey(x509Representation: x509Data)
    }

    func testX509Conversion() throws {
        let rsaPrivateKey = try Crypto.RSA.PrivateKey(bitCount: 2048)
        let x509Representation = rsaPrivateKey.publicKey().x509Representation
        expect(x509Representation.isEmpty) == false
    }
}

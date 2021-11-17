// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import XCTest

class ECCPrivateKeyTests: XCTestCase {
    func testECCPrivateKeyCreation() throws {
        let privateKey = Crypto.ECC.PrivateKey(curve: .P256)

        let privateKey2 = try Crypto.ECC.PrivateKey(x963Representation: privateKey.x963Representation)
        expect(privateKey.x963Representation) == privateKey2.x963Representation

        let privateKey3 = try Crypto.ECC.PrivateKey(secKey: privateKey.secKey)
        expect(privateKey.x963Representation) == privateKey3.x963Representation
    }

    func testInvalidECCPrivateKeyCreationFromSecKey() throws {
        let privateKey = Crypto.ECC.PrivateKey(curve: .P256)
        let publicKey: Crypto.ECC.PublicKey = privateKey.publicKey()

        expect {
            _ = try Crypto.ECC.PrivateKey(secKey: publicKey.secKey)
        }.to(throwError(Crypto.KeyError.invalidSecKey))
    }
}

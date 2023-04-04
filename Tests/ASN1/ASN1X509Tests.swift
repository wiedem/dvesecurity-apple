// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import SwiftASN1
import XCTest

final class ASN1X509Tests: XCTestCase {
    private lazy var x509TestFileURL = Bundle.main.url(forResource: "X509RSAPublicKey", withExtension: "der")!

    func testGetRSAPublicKeyFromX509PublicKeyInfo() throws {
        let x509Data = try Data(contentsOf: x509TestFileURL)

        let node = try DER.parse(Array(x509Data))
        let subjectPublicKeyInfo = try ASN1.X509.SubjectPublicKeyInfo(derEncoded: node)

        expect { () -> Void in
            _ = try subjectPublicKeyInfo.pkcs1RSAPublicKey()
        }.toNot(throwError())
    }
}

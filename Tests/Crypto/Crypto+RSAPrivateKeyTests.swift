// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import XCTest

final class RSAPrivateKeyTests: XCTestCase {
    func testMaxPlainTextLength() throws {
        let rsaPrivateKey = try Crypto.RSA.PrivateKey(bitCount: 2048)
        let keyBlockSize = rsaPrivateKey.blockSize

        for algorithm in Crypto.RSA.EncryptionAlgorithm.allCases {
            let maxPlainTextLength = rsaPrivateKey.maxPlainTextLength(for: algorithm)

            switch algorithm {
            case .raw:
                expect(maxPlainTextLength) == keyBlockSize
            case .pkcs1:
                expect(maxPlainTextLength) == keyBlockSize - 11
            case .oaepSHA1:
                expect(maxPlainTextLength) == keyBlockSize - 42
            case .oaepSHA224:
                expect(maxPlainTextLength) == keyBlockSize - 58
            case .oaepSHA256:
                expect(maxPlainTextLength) == keyBlockSize - 66
            case .oaepSHA384:
                expect(maxPlainTextLength) == keyBlockSize - 98
            case .oaepSHA512:
                expect(maxPlainTextLength) == keyBlockSize - 130
            default:
                expect(maxPlainTextLength).to(beNil())
            }
        }
    }

    func testRSAPrivateKeyCreation() throws {
        let privateKey = try Crypto.RSA.PrivateKey(bitCount: 2048)

        let privateKey2 = try Crypto.RSA.PrivateKey(pkcs1Representation: privateKey.pkcs1Representation)
        expect(privateKey.pkcs1Representation) == privateKey2.pkcs1Representation

        let privateKey3 = try Crypto.RSA.PrivateKey(secKey: privateKey.secKey)
        expect(privateKey.pkcs1Representation) == privateKey3.pkcs1Representation
    }

    func testInvalidRSAPrivateKeyCreation() throws {
        expect {
            _ = try Crypto.RSA.PrivateKey(bitCount: 1)
        }.to(throwError { error in
            let nsError = error as NSError
            expect(nsError.domain) == NSOSStatusErrorDomain
            expect(nsError.code) == Int(errSecParam)
        })
    }

    func testInvalidRSAPrivateKeyCreationFromSecKey() throws {
        let privateKey = try Crypto.RSA.PrivateKey(bitCount: 1024)
        let publicKey = privateKey.publicKey()

        expect {
            _ = try Crypto.RSA.PrivateKey(secKey: publicKey.secKey)
        }.to(throwError(Crypto.KeyError.invalidSecKey))
    }
}

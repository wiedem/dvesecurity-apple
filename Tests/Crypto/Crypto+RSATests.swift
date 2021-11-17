// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import XCTest

class RSATests: XCTestCase {
    func testEncryptionAndDecryption() throws {
        let rsaPrivateKey = try Crypto.RSA.PrivateKey(bitCount: 2048)
        let rsaPublicKey = rsaPrivateKey.publicKey()

        let plainText = "Hello World!"
        let plainTextData = plainText.data(using: .utf8)!

        // Raw encrypting/decryption needs a manual data padding.
        let rawDataLength = rsaPrivateKey.maxPlainTextLength(for: .raw)!
        let paddedPlainText = plainText.padding(toLength: rawDataLength, withPad: "P", startingAt: 0)
        let paddedPlainTextData = paddedPlainText.data(using: .utf8)!
        let cipherTextData = try rsaPublicKey.encrypt(paddedPlainTextData, using: .raw)
        let decryptedPaddedData = try rsaPrivateKey.decrypt(cipherTextData, using: .raw)
        let decryptedPaddedText = String(data: decryptedPaddedData, encoding: .utf8)!
        expect(decryptedPaddedText) == paddedPlainText

        // Test all other algorithms.
        var algorithms = Crypto.RSA.EncryptionAlgorithm.allCases
        let rawIndex = algorithms.firstIndex(of: .raw)!
        algorithms.remove(at: rawIndex)

        for algorithm in algorithms {
            let cipherTextData = try rsaPublicKey.encrypt(plainTextData, using: algorithm)
            let decryptedData = try rsaPrivateKey.decrypt(cipherTextData, using: algorithm)
            let decryptedText = String(data: decryptedData, encoding: .utf8)!

            expect(decryptedText).to(equal(plainText), description: "Decrypted text with RSA algorithm '\(algorithm)'")
        }
    }

    func testEncryptionWithInvalidDataLength() throws {
        let rsaPrivateKey = try Crypto.RSA.PrivateKey(bitCount: 2048)
        let rsaPublicKey = rsaPrivateKey.publicKey()

        let algorithms = Crypto.RSA.EncryptionAlgorithm.allCases.filter { rsaPrivateKey.maxPlainTextLength(for: $0) != nil }
        for algorithm in algorithms {
            let maxPlainTextLength = rsaPrivateKey.maxPlainTextLength(for: algorithm)!
            let plainTextData = String(repeating: "A", count: maxPlainTextLength + 1).data(using: .utf8)!

            expect {
                _ = try rsaPublicKey.encrypt(plainTextData, using: algorithm)
            }.to(throwError {
                expect($0) == Crypto.RSAError.invalidDataLength
            })
        }
    }

    func testDecryptionWithInvalidDataAndMaxDataLength() throws {
        let rsaPrivateKey = try Crypto.RSA.PrivateKey(bitCount: 2048)
        let cipherTextData = Data(count: rsaPrivateKey.blockSize)

        let algorithms = Crypto.RSA.EncryptionAlgorithm.allCases.filter { rsaPrivateKey.maxPlainTextLength(for: $0) != nil }
        for algorithm in algorithms {
            expect({ () -> ToSucceedResult in
                do {
                    _ = try rsaPrivateKey.decrypt(cipherTextData, using: algorithm)
                } catch Crypto.RSAError.invalidDataLength {
                    return .failed(reason: "RSA decryption was not supposed to throw an invalid data length error for algorithm '\(algorithm)'")
                } catch {
                    return .succeeded
                }
                return .succeeded
            }).to(succeed())
        }
    }

    func testDecryptionWithInvalidDataLength() throws {
        let rsaPrivateKey = try Crypto.RSA.PrivateKey(bitCount: 2048)

        let algorithms = Crypto.RSA.EncryptionAlgorithm.allCases.filter { rsaPrivateKey.maxPlainTextLength(for: $0) != nil }
        for algorithm in algorithms {
            let cipherTextData = Data(count: rsaPrivateKey.blockSize + 1)

            expect {
                _ = try rsaPrivateKey.decrypt(cipherTextData, using: algorithm)
            }.to(throwError {
                expect($0) == Crypto.RSAError.invalidDataLength
            })
        }
    }

    func testSignAndVerify() throws {
        let rsaPrivateKey = try Crypto.RSA.PrivateKey(bitCount: 2048)
        let rsaPublicKey = rsaPrivateKey.publicKey()

        let plainText = "Hello World!"
        let plainTextData = plainText.data(using: .utf8)!
        let otherPlainText = "Test"
        let otherPlainTextData = otherPlainText.data(using: .utf8)!

        for algorithm in Crypto.RSA.SignatureAlgorithm.allCases {
            expect { () -> Void in
                let signatureData = try rsaPrivateKey.signature(for: plainTextData, algorithm: algorithm)
                let verifyResult1 = try rsaPublicKey.isValidSignature(signatureData, for: plainTextData, algorithm: algorithm)
                expect(verifyResult1) == true

                let verifyResult2 = try rsaPublicKey.isValidSignature(signatureData, for: otherPlainTextData, algorithm: algorithm)
                expect(verifyResult2) == false
            }.toNot(throwError(), description: "RSA signing and signature verification with algorithm '\(algorithm)' failed.")
        }
    }
}

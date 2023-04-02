// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import XCTest

final class RSATests: XCTestCase {
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

    func testSignMessageAndVerify() throws {
        let rsaPrivateKey = try Crypto.RSA.PrivateKey(bitCount: 2048)
        let rsaPublicKey = rsaPrivateKey.publicKey()

        let plainText = "Hello World!"
        let plainTextData = plainText.data(using: .utf8)!
        let otherPlainText = "Test"
        let otherPlainTextData = otherPlainText.data(using: .utf8)!

        for algorithm in Crypto.RSA.MessageSignatureAlgorithm.allCases {
            expect { () in
                let signatureData = try rsaPrivateKey.signature(for: plainTextData, algorithm: algorithm)
                let verifyResult1 = try rsaPublicKey.isValidSignature(signatureData, of: plainTextData, algorithm: algorithm)
                expect(verifyResult1) == true

                let verifyResult2 = try rsaPublicKey.isValidSignature(signatureData, of: otherPlainTextData, algorithm: algorithm)
                expect(verifyResult2) == false
            }.toNot(throwError(), description: "RSA signing and signature verification with algorithm '\(algorithm)' failed.")
        }
    }

    func testSignDigestPKCSv15RawAndVerify() throws {
        let rsaPrivateKey = try Crypto.RSA.PrivateKey(bitCount: 2048)
        let rsaPublicKey = rsaPrivateKey.publicKey()

        let plainText = "Hello World!"
        let plainTextData = plainText.data(using: .utf8)!

        let hashFunctions: [HashFunction.Type] = [
            Hashing.SHA224.self,
            Hashing.SHA256.self,
            Hashing.SHA384.self,
            Hashing.SHA512.self,
        ]

        for hashFunction in hashFunctions {
            expect { () in
                let digest = hashFunction.hash(plainTextData)
                let signatureData = try rsaPrivateKey.digestSignature(for: digest, algorithm: .PKCS1v15Raw)
                let verifyResult = try rsaPublicKey.isValidDigestSignature(signatureData, digest: digest, algorithm: .PKCS1v15Raw)

                expect(verifyResult) == true
            }.toNot(throwError())
        }
    }

    func testSignDigestPKCS1v15AndVerify() throws {
        let rsaPrivateKey = try Crypto.RSA.PrivateKey(bitCount: 2048)
        let rsaPublicKey = rsaPrivateKey.publicKey()

        let plainText = "Hello World!"
        let plainTextData = plainText.data(using: .utf8)!

        let hashFunctions: [HashFunction.Type] = [
            Hashing.SHA224.self,
            Hashing.SHA256.self,
            Hashing.SHA384.self,
            Hashing.SHA512.self,
        ]

        for hashFunction in hashFunctions {
            expect { () in
                let digest = hashFunction.hash(plainTextData)

                let algorithm = Self.pkcs1v15DigestSignatureAlgorithm(for: hashFunction)
                let signatureData = try rsaPrivateKey.digestSignature(for: digest, algorithm: algorithm)
                let verifyResult = try rsaPublicKey.isValidDigestSignature(signatureData, digest: digest, algorithm: algorithm)

                expect(verifyResult) == true
            }.toNot(throwError())
        }
    }

    func testSignDigestPKCS1v21AndVerify() throws {
        let rsaPrivateKey = try Crypto.RSA.PrivateKey(bitCount: 2048)
        let rsaPublicKey = rsaPrivateKey.publicKey()

        let plainText = "Hello World!"
        let plainTextData = plainText.data(using: .utf8)!

        let hashFunctions: [HashFunction.Type] = [
            Hashing.SHA224.self,
            Hashing.SHA256.self,
            Hashing.SHA384.self,
            Hashing.SHA512.self,
        ]

        for hashFunction in hashFunctions {
            expect { () in
                let digest = hashFunction.hash(plainTextData)

                let algorithm = Self.pkcs1v21DigestSignatureAlgorithm(for: hashFunction)
                let signatureData = try rsaPrivateKey.digestSignature(for: digest, algorithm: algorithm)
                let verifyResult = try rsaPublicKey.isValidDigestSignature(signatureData, digest: digest, algorithm: algorithm)

                expect(verifyResult) == true
            }.toNot(throwError())
        }
    }

    func testSignDigestWithInvalidAlgorithm() throws {
        let rsaPrivateKey = try Crypto.RSA.PrivateKey(bitCount: 2048)
        let rsaPublicKey = rsaPrivateKey.publicKey()

        let plainText = "Hello World!"
        let plainTextData = plainText.data(using: .utf8)!

        expect { () in
            let digest = Hashing.SHA224.hash(plainTextData)

            let algorithm = Crypto.RSA.DigestSignatureAlgorithm.PKCS1v15SHA256
            let signatureData = try rsaPrivateKey.digestSignature(for: digest, algorithm: algorithm)
            let verifyResult = try rsaPublicKey.isValidDigestSignature(signatureData, digest: digest, algorithm: algorithm)

            expect(verifyResult) == true
        }.toNot(throwError())
    }
}

private extension RSATests {
    static func pkcs1v15DigestSignatureAlgorithm(for hashFunctionType: (some HashFunction).Type) -> Crypto.RSA.DigestSignatureAlgorithm {
        switch hashFunctionType {
        case is Hashing.SHA224.Type:
            return .PKCS1v15SHA224
        case is Hashing.SHA256.Type:
            return .PKCS1v15SHA256
        case is Hashing.SHA384.Type:
            return .PKCS1v15SHA384
        case is Hashing.SHA512.Type:
            return .PKCS1v15SHA512
        default:
            fatalError("Unknown hash function type '\(hashFunctionType)'")
        }
    }

    static func pkcs1v21DigestSignatureAlgorithm(for hashFunctionType: (some HashFunction).Type) -> Crypto.RSA.DigestSignatureAlgorithm {
        switch hashFunctionType {
        case is Hashing.SHA224.Type:
            return .PSSSHA224
        case is Hashing.SHA256.Type:
            return .PSSSHA256
        case is Hashing.SHA384.Type:
            return .PSSSHA384
        case is Hashing.SHA512.Type:
            return .PSSSHA512
        default:
            fatalError("Unknown hash function type '\(hashFunctionType)'")
        }
    }
}

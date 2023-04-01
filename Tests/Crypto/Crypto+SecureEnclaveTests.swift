// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import XCTest

final class Crypto_SecureEnclaveTests: TestCaseDevice {
    func testEncryptionAndDecryption() throws {
        let secureEnclaveKey = try Crypto.ECC.SecureEnclaveKey()
        let publicKey: Crypto.ECC.PublicKey = secureEnclaveKey.publicKey()

        let plainText = "Hello World!"
        let plainTextData = plainText.data(using: .utf8)!

        for algorithm in Crypto.ECC.EncryptionAlgorithm.allCases {
            let cipherTextData = try publicKey.encrypt(plainTextData, using: algorithm)
            let decryptedData = try secureEnclaveKey.decrypt(cipherTextData, using: algorithm)
            let decryptedText = String(data: decryptedData, encoding: .utf8)!

            expect(decryptedText).to(equal(plainText), description: "Decrypted text with ECC algorithm '\(algorithm)'")
        }
    }

    func testSignAndVerify() throws {
        let secureEnclaveKey = try Crypto.ECC.SecureEnclaveKey()
        let publicKey: Crypto.ECC.PublicKey = secureEnclaveKey.publicKey()

        let plainText = "Hello World!"
        let plainTextData = plainText.data(using: .utf8)!
        let otherPlainText = "Test"
        let otherPlainTextData = otherPlainText.data(using: .utf8)!

        for algorithm in Crypto.ECC.SignatureAlgorithm.allCases {
            expect { () in
                let signatureData = try secureEnclaveKey.signature(for: plainTextData, algorithm: algorithm)
                let verifyResult1 = try publicKey.isValidSignature(signatureData, for: plainTextData, algorithm: algorithm)
                expect(verifyResult1) == true

                let verifyResult2 = try publicKey.isValidSignature(signatureData, for: otherPlainTextData, algorithm: algorithm)
                expect(verifyResult2) == false
            }.toNot(throwError(), description: "ECC Secure Enclave signing and signature verification with algorithm '\(algorithm)' failed.")
        }
    }
}

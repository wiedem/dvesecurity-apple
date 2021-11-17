// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import XCTest

class AESTests: XCTestCase {
    func testEncryptionAndDecryption() throws {
        let ivData = try Crypto.AES.createIV()
        let aesKey = try Crypto.AES.Key(keySize: .bits192, password: "Password", withSalt: "Salt", pseudoRandomAlgorithm: .hmacAlgSHA256, rounds: 1)

        // Test plaintext data smaller than the AES block size.
        let plainText1 = String(repeating: "A", count: Crypto.AES.blockSize - 1)
        let plainTextData1 = plainText1.data(using: .utf8)!

        let decryptedPlainTextData1 = try encryptAndDecrypt(plainTextData1, withKey: aesKey, ivData: ivData)
        expect(decryptedPlainTextData1) == plainTextData1

        // Test plaintext data with equal size of the AES block size.
        let plainText2 = String(repeating: "B", count: Crypto.AES.blockSize)
        let plainTextData2 = plainText2.data(using: .utf8)!

        let decryptedPlainTextData2 = try encryptAndDecrypt(plainTextData2, withKey: aesKey, ivData: ivData)
        expect(decryptedPlainTextData2) == plainTextData2

        // Test plaintext data with size bigger than the AES block size.
        let plainText3 = String(repeating: "C", count: Crypto.AES.blockSize + 1)
        let plainTextData3 = plainText3.data(using: .utf8)!

        let decryptedPlainTextData3 = try encryptAndDecrypt(plainTextData3, withKey: aesKey, ivData: ivData)
        expect(decryptedPlainTextData3) == plainTextData3
    }

    func testCryptOperationWithInvalidIVSize() throws {
        let ivData = Data(count: 1)
        let plainText = String(repeating: "B", count: Crypto.AES.blockSize)
        let data = plainText.data(using: .utf8)!

        let aesKey = try Crypto.AES.Key(keySize: .bits192, password: "Password", withSalt: "Salt", pseudoRandomAlgorithm: .hmacAlgSHA256, rounds: 1)

        expect {
            _ = try Crypto.AES.encrypt(data, withKey: aesKey, ivData: ivData)
        }.to(throwError {
            expect($0) == Crypto.AESError.invalidIVSize(Crypto.AES.blockSize)
        })

        expect {
            _ = try Crypto.AES.decrypt(data, withKey: aesKey, ivData: ivData)
        }.to(throwError {
            expect($0) == Crypto.AESError.invalidIVSize(Crypto.AES.blockSize)
        })
    }
}

private extension AESTests {
    func encryptAndDecrypt(_ plainText: Data, withKey key: Crypto.AES.Key, ivData: Data) throws -> Data {
        let cipherText = try key.encrypt(plainText, ivData: ivData)
        return try key.decrypt(cipherText, ivData: ivData)
    }
}

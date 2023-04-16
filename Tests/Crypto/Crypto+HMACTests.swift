// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Foundation
import Nimble
import XCTest

final class Crypto_HMACTests: XCTestCase {
    private lazy var testFileURL = Bundle.main.url(forResource: "test", withExtension: "dat")!

    func testValidAuthenticationCode() throws {
        let data = "Hello World!".data(using: .utf8)!
        let keyData = try Crypto.KeyData.createRandomData(length: 32)
        let code = Crypto.HMAC<Hashing.SHA256>.authenticationCode(for: data, keyData: keyData)

        let isCodeValid = Crypto.HMAC<Hashing.SHA256>.isValidAuthenticationCode(code, authenticating: data, keyData: keyData)
        expect(isCodeValid) == true
    }

    func testValidAuthenticationCodeWithAESKey() throws {
        let data = "Hello World!".data(using: .utf8)!
        let key = try Crypto.AES.Key.createRandom(.bits256)
        let code = Crypto.HMAC<Hashing.SHA256>.authenticationCode(for: data, key: key)

        let isCodeValid = Crypto.HMAC<Hashing.SHA256>.isValidAuthenticationCode(code, authenticating: data, key: key)
        expect(isCodeValid) == true
    }

    func testInvalidAuthenticationCode() throws {
        let data = "Hello World!".data(using: .utf8)!
        let keyData = try Crypto.KeyData.createRandomData(length: 32)
        let code = Crypto.HMAC<Hashing.SHA256>.authenticationCode(for: data, keyData: keyData)

        let tamperedData = "Manipulated".data(using: .utf8)!
        let tamperedKeyData = try Crypto.KeyData.createRandomData(length: 32)

        let isCodeValid1 = Crypto.HMAC<Hashing.SHA256>.isValidAuthenticationCode(code, authenticating: tamperedData, keyData: keyData)
        expect(isCodeValid1) == false

        let isCodeValid2 = Crypto.HMAC<Hashing.SHA256>.isValidAuthenticationCode(code, authenticating: data, keyData: tamperedKeyData)
        expect(isCodeValid2) == false
    }

    func testIncrementalAuthenticationCode() throws {
        try performIncrementalTest(for: Hashing.SHA224.self)
        try performIncrementalTest(for: Hashing.SHA256.self)
        try performIncrementalTest(for: Hashing.SHA384.self)
        try performIncrementalTest(for: Hashing.SHA512.self)
    }
}

private extension Crypto_HMACTests {
    func performIncrementalTest<H>(for hashFunction: H.Type) throws where H: HashFunction & CCHmacAlgorithmMapping {
        let key = try Crypto.AES.Key(keySize: .bits256, password: "Password", withSalt: "Salt", pseudoRandomAlgorithm: .hmacAlgSHA256, rounds: 1)

        var hmac = Crypto.HMAC<H>(key: key)

        let fileHandle = try FileHandle(forReadingFrom: testFileURL)
        defer { fileHandle.closeFile() }

        var bytesRead = 0
        repeat {
            let fileData = fileHandle.readData(ofLength: 512)
            bytesRead = fileData.count
            hmac.update(data: fileData)
        } while bytesRead > 0

        let code = hmac.finalize()

        let fileData = try Data(contentsOf: testFileURL, options: .dataReadingMapped)
        let valid = Crypto.HMAC<H>.isValidAuthenticationCode(code, authenticating: fileData, key: key)

        expect(valid) == true
    }
}

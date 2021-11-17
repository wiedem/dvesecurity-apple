// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Foundation
import Nimble
import XCTest

class Crypto_HMACTests: XCTestCase {
    private lazy var testFileURL = Bundle.main.url(forResource: "test", withExtension: "dat")!

    func testAuthenticationCode() throws {
        let data = "Hello World!".data(using: .utf8)!

        let key = try Crypto.AES.Key(keySize: .bits256, password: "Password", withSalt: "Salt", pseudoRandomAlgorithm: .hmacAlgSHA256, rounds: 1)

        let code = Crypto.HMAC<Hashing.SHA256>.authenticationCode(for: data, using: key)
        let valid = Crypto.HMAC<Hashing.SHA256>.isValidAuthenticationCode(code, authenticating: data, using: key)

        expect(valid) == true
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
        let valid = Crypto.HMAC<H>.isValidAuthenticationCode(code, authenticating: fileData, using: key)

        expect(valid) == true
    }
}

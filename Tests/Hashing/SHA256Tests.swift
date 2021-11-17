// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import CommonCrypto
import Nimble
import XCTest

class SHA256Tests: HashingTests {
    private lazy var data = "Hello World!".data(using: .utf8)!
    private let dataHash: [UInt8] = [0x7F, 0x83, 0xB1, 0x65, 0x7F, 0xF1, 0xFC, 0x53,
                                     0xB9, 0x2D, 0xC1, 0x81, 0x48, 0xA1, 0xD6, 0x5D,
                                     0xFC, 0x2D, 0x4B, 0x1F, 0xA3, 0xD6, 0x77, 0x28,
                                     0x4A, 0xDD, 0xD2, 0x00, 0x12, 0x6D, 0x90, 0x69]
    private lazy var testFileURL = Bundle.main.url(forResource: "test", withExtension: "dat")!
    private let testFileHash: [UInt8] = [0x4E, 0xBD, 0x08, 0x5A, 0x1C, 0xE2, 0xF1, 0x77,
                                         0xFA, 0xEB, 0xC3, 0x44, 0x91, 0x71, 0x16, 0x6D,
                                         0xB2, 0xD4, 0x6A, 0x45, 0xD9, 0xCD, 0xD5, 0x8D,
                                         0x49, 0xD5, 0x98, 0x75, 0x81, 0x54, 0xFF, 0x35]

    func testSHA256() {
        expect(Hashing.SHA256.blockByteCount) == Int(CC_SHA256_BLOCK_BYTES)

        performHashTest(for: Hashing.SHA256.self, data: data, expectedHash: Data(dataHash))
    }

    func testSHA256IncrementalHash() throws {
        try performIncrementalHashTest(for: Hashing.SHA256.self, fileURL: testFileURL, expectedHash: Data(testFileHash))
    }
}

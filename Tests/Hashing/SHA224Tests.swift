// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import CommonCrypto
import Nimble
import XCTest

final class SHA224Tests: HashingTests {
    private lazy var data = "Hello World!".data(using: .utf8)!
    private let dataHash: [UInt8] = [0x45, 0x75, 0xBB, 0x4E, 0xC1, 0x29, 0xDF, 0x63,
                                     0x80, 0xCE, 0xDD, 0xE6, 0xD7, 0x12, 0x17, 0xFE,
                                     0x05, 0x36, 0xF8, 0xFF, 0xC4, 0xE1, 0x8B, 0xCA,
                                     0x53, 0x0A, 0x7A, 0x1B]
    private lazy var testFileURL = Bundle.main.url(forResource: "test", withExtension: "dat")!
    private let testFileHash: [UInt8] = [0x02, 0xEA, 0x5F, 0x90, 0x09, 0xF1, 0x3F, 0x61,
                                         0xE7, 0x18, 0x1A, 0x6C, 0x93, 0x97, 0x11, 0xB6,
                                         0x39, 0x65, 0xB4, 0xD1, 0xD4, 0x79, 0x35, 0xB8,
                                         0x0C, 0xF7, 0xE5, 0xEE]

    func testSHA224() {
        expect(Hashing.SHA224.blockByteCount) == Int(CC_SHA224_BLOCK_BYTES)

        performHashTest(for: Hashing.SHA224.self, data: data, expectedHash: Data(dataHash))
    }

    func testSHA224IncrementalHash() throws {
        try performIncrementalHashTest(for: Hashing.SHA224.self, fileURL: testFileURL, expectedHash: Data(testFileHash))
    }
}

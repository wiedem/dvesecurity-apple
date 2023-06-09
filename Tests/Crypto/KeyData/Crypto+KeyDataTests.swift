// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import XCTest

final class Crypto_KeyDataTests: XCTestCase {
    func testSecureDataTransfer() throws {
        let bytes: [UInt8] = [0x01, 0x02, 0x03, 0x04]
        let mutableData = NSMutableData(bytes: bytes, length: bytes.count)
        let dataPointer = mutableData.bytes.bindMemory(to: UInt8.self, capacity: bytes.count)

        let keyData: Crypto.KeyData! = .init(transferFrom: mutableData)
        expect(keyData.byteCount) == bytes.count

        for index in 0..<bytes.count {
            expect(dataPointer[index]) == 0
        }
    }
}

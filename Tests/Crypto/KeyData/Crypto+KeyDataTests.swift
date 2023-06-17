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

    func testCompare() {
        let bytes1: [UInt8] = [0x01, 0x02, 0x03, 0x04]
        let bytes2: [UInt8] = [0x04, 0x03, 0x02, 0x01]
        let bytes3: [UInt8] = [0x01, 0x02, 0x03, 0x04]

        let data1 = NSMutableData(bytes: bytes1, length: bytes1.count)
        let data2 = NSMutableData(bytes: bytes2, length: bytes2.count)
        let data3 = NSMutableData(bytes: bytes3, length: bytes3.count)

        let keyData1 = Crypto.KeyData(transferFrom: data1)
        let keyData2 = Crypto.KeyData(transferFrom: data2)
        let keyData3 = Crypto.KeyData(transferFrom: data3)

        expect(keyData1) != keyData2
        expect(keyData1) == keyData3
    }
}

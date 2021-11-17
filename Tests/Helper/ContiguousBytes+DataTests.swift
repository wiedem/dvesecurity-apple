// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import XCTest

class ContiguousBytes_DataTests: XCTestCase {
    func testDataConversionWithEmptyBytes() throws {
        let emptyData = Data()

        let dataNoCopy = emptyData.dataNoCopy
        expect(dataNoCopy.isEmpty) == true
    }

    func testDataConversion() throws {
        let data = Data([0x01, 0x02, 0x03, 0x04])

        let dataNoCopy = data.dataNoCopy
        expect(dataNoCopy.isEmpty) == false
        expect(dataNoCopy) == data
    }

    func testDataConversionWithMutation() throws {
        var data = Data([0x01, 0x02, 0x03, 0x04])

        let dataNoCopy = data.dataNoCopy
        data.removeLast(2)
        data.append(contentsOf: [0x05])

        expect(data) == Data([0x01, 0x02, 0x05])
        expect(dataNoCopy) == Data([0x01, 0x02, 0x03, 0x04])
    }
}

// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import XCTest

class HashingTests: XCTestCase {
    func performHashTest<H>(for hashFunction: H.Type, data: Data, expectedHash: Data) where H: HashFunction {
        let hash = H.hash(data)
        expect(hash) == expectedHash
    }

    func performIncrementalHashTest<H>(for hashFunction: H.Type, fileURL: URL, expectedHash: Data) throws where H: HashFunction {
        var hashFunction = H()

        let fileHandle = try FileHandle(forReadingFrom: fileURL)
        defer { fileHandle.closeFile() }

        var bytesRead = 0
        repeat {
            let fileData = fileHandle.readData(ofLength: 512)
            bytesRead = fileData.count
            hashFunction.update(data: fileData)
        } while bytesRead > 0

        let hash = hashFunction.finalize()
        expect(hash) == Data(expectedHash)
    }
}

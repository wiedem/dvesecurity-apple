// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import XCTest

class Optional_SetElementTests: XCTestCase {
    func testUpdateMapped() throws {
        var collection: Set<String> = ["1", "2"]

        var optionalItem: Int?
        optionalItem.updateMapped({ "\($0)" }, in: &collection)
        expect(collection).toNot(contain("3"))

        optionalItem = 3
        optionalItem.updateMapped({ "\($0)" }, in: &collection)
        expect(collection).to(contain("1", "2", "3"))
    }
}

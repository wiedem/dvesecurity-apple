// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import XCTest

class TestCaseiOS13: XCTestCase {
    override func setUpWithError() throws {
        guard #available(iOS 13.0, *) else {
            throw XCTSkip("Test case requires a iOS 13 compatible platform.")
        }
        try super.setUpWithError()
    }

    override func tearDownWithError() throws {
        try super.tearDownWithError()

        guard let testRun, testRun.hasBeenSkipped == false else {
            throw XCTSkip("Test case requires a iOS 13 compatible platform.")
        }
    }
}

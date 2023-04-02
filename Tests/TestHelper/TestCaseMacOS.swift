// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import XCTest

class TestCaseMacOS: XCTestCase {
    override func setUpWithError() throws {
        #if !os(macOS)
        throw XCTSkip("Test case needs to run on the macOS platform.")
        #else
        try super.setUpWithError()
        #endif
    }

    override func tearDownWithError() throws {
        try super.tearDownWithError()

        guard let testRun, testRun.hasBeenSkipped == false else {
            throw XCTSkip("Test case needs to run on the macOS platform.")
        }
    }
}

// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import XCTest

class TestCaseDevice: XCTestCase {
    override func setUpWithError() throws {
        #if targetEnvironment(simulator)
        throw XCTSkip("Test case needs to run on an actual device.")
        #else
        try super.setUpWithError()
        #endif
    }

    override func tearDownWithError() throws {
        try super.tearDownWithError()

        guard let testRun, testRun.hasBeenSkipped == false else {
            throw XCTSkip("Test case needs to run on an actual device.")
        }
    }
}

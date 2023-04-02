// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import XCTest

class TestCaseiOS13Device: XCTestCase {
    override func setUpWithError() throws {
        #if targetEnvironment(simulator)
        throw XCTSkip("Test case needs to run on an actual device.")
        #else
        guard #available(iOS 13.0, *) else {
            throw XCTSkip("Test case needs to run on an iOS 13 compatible device.")
        }
        try super.setUpWithError()
        #endif
    }

    override func tearDownWithError() throws {
        try super.tearDownWithError()

        guard let testRun, testRun.hasBeenSkipped == false else {
            throw XCTSkip("Test case needs to run on an iOS 13 compatible device.")
        }
    }
}

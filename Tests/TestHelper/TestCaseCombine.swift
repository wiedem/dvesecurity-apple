// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import XCTest

class TestCaseCombine: XCTestCase {
    override func setUpWithError() throws {
        guard #available(macOS 10.15, iOS 13.0, *) else {
            throw XCTSkip("Test case requires at least macOS 10.15 or iOS 13.")
        }

        #if !canImport(Combine)
        throw XCTSkip("Test case needs the Combine framework to run.")
        #else
        try super.setUpWithError()
        #endif
    }

    override func tearDownWithError() throws {
        try super.tearDownWithError()

        guard let testRun, testRun.hasBeenSkipped == false else {
            throw XCTSkip("Test case requires at least macOS 10.15 or iOS 13 and the Combine framework to run.")
        }
    }
}

// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import XCTest

class TestCaseCryptoKit: TestCaseiOS13 {
    override func setUpWithError() throws {
        #if !canImport(CryptoKit)
        throw XCTSkip("Test case needs the CryptoKit framework to run.")
        #else
        try super.setUpWithError()
        #endif
    }

    override func tearDownWithError() throws {
        try super.tearDownWithError()

        guard let testRun, testRun.hasBeenSkipped == false else {
            throw XCTSkip("Test case needs the CryptoKit framework to run.")
        }
    }
}

// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurityTestApp
import XCTest
#if os(iOS)
import UIKit
#elseif os(macOS)
import Cocoa
#endif

class InteractiveTestCase: XCTestCase {
    var testViewModel: InteractiveTestViewModel {
        #if os(iOS)
        let window = UIApplication.shared.keyWindow!
        return window.rootViewController as! InteractiveTestViewModel
        #elseif os(macOS)
        let window = NSApplication.shared.windows.first!
        return window.contentViewController as! InteractiveTestViewModel
        #endif
    }

    override func setUpWithError() throws {
        continueAfterFailure = false

        try super.setUpWithError()
    }
}

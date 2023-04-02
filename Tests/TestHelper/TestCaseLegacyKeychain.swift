// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import DVESecurity
import Security
import XCTest

#if os(macOS)
class TestCaseLegacyKeychain: TestCaseMacOS {
    private(set) var keychain: SecKeychain!
    private var tempURL: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()

        tempURL = try FileManager.default.url(for: .itemReplacementDirectory,
                                              in: .userDomainMask,
                                              appropriateFor: FileManager.default.temporaryDirectory,
                                              create: true)
        let keychainURL = tempURL.appendingPathComponent("keychain.db")

        keychain = try Keychain.Legacy.createKeychain(pathName: keychainURL.relativePath, password: "Test123")
    }

    override func tearDownWithError() throws {
        if let keychain {
            try Keychain.Legacy.deleteKeychain(keychain)
        }
        try FileManager.default.removeItem(at: tempURL)

        try super.tearDownWithError()
    }
}
#endif

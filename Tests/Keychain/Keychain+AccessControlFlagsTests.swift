// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import XCTest

class Keychain_AccessControlFlagsTests: XCTestCase {
    func testAccessControlFlagsSetMethods() {
        var flags: Keychain.AccessControlFlags = []
        var count = 0

        for flag in Keychain.AccessControlFlag.allCases {
            flags.update(with: flag)

            expect(flags.count) == count + 1
            expect(flags.contains(flag)) == true
            count += 1
        }

        flags.removeAll()
        expect(flags.isEmpty) == true

        flags.insert(.biometryAny)
        expect(flags.count) == 1
        expect(flags) == [.biometryAny]

        flags.insert(.biometryAny)
        expect(flags.count) == 1
        expect(flags) == [.biometryAny]
    }

    func testAccessControlFlagsWithApplicationPasswortInsertion() {
        var flags: Keychain.AccessControlFlags = [.biometryAny]

        // Conditional insert
        flags.insert(.applicationPassword())
        expect(flags.count) == 2
        expect(flags.applicationPasswordPrompt).to(beNil())

        flags.insert(.applicationPassword(prompt: "Test"))
        expect(flags.count) == 2
        expect(flags.applicationPasswordPrompt).to(beNil())

        // Unconditional update
        flags.update(with: .applicationPassword(prompt: nil))
        expect(flags.count) == 2
        expect(flags.applicationPasswordPrompt).to(beNil())

        flags.update(with: .applicationPassword(prompt: "Test1"))
        expect(flags.count) == 2
        expect(flags.applicationPasswordPrompt) == "Test1"

        flags.update(with: .applicationPassword(prompt: "Test2"))
        expect(flags.count) == 2
        expect(flags.applicationPasswordPrompt) == "Test2"

        flags.update(with: .applicationPassword(prompt: nil))
        expect(flags.count) == 2
        expect(flags.applicationPasswordPrompt).to(beNil())

        // Removal
        flags.remove(.applicationPassword())
        expect(flags.count) == 1
    }

    func testAccessControlFlagsHashable() {
        let flags1: Keychain.AccessControlFlags = [.biometryAny, .applicationPassword()]
        let flags2: Keychain.AccessControlFlags = [.applicationPassword(), .biometryAny]
        let flags3: Keychain.AccessControlFlags = [.biometryAny, .applicationPassword(prompt: "Test")]

        expect(flags1) == flags2
        expect(flags1) != flags3
        expect(flags1.hashValue) == flags2.hashValue
        expect(flags1.hashValue) != flags3.hashValue
        expect(flags2.hashValue) != flags3.hashValue
    }
}

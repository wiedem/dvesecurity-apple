// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import XCTest

#if os(macOS)
final class Keychain_Legacy_InternetPasswordTests: TestCaseLegacyKeychain {
    private let password = "Password-1234!äöü/"
    private let account1 = "InternetPasswordTest1"
    private let account2 = "InternetPasswordTest2"

    override func tearDownWithError() throws {
        try Keychain.Legacy.InternetPassword.deleteItems(forAccount: account1, inKeychain: keychain)
        try Keychain.Legacy.InternetPassword.deleteItems(forAccount: account2, inKeychain: keychain)

        try super.tearDownWithError()
    }

    func testSaveAndQuery() throws {
        try Keychain.Legacy.InternetPassword.save(password, forAccount: account1, label: "Test", inKeychain: keychain)

        let queriedPassword = try Keychain.Legacy.InternetPassword.queryOne(forAccount: account1, inKeychain: keychain)
        expect(queriedPassword) == password
    }

    func testSaveAndQueryMultipleItems() throws {
        try Keychain.Legacy.InternetPassword.save("Test1", forAccount: account1, label: "Test", inKeychain: keychain)
        try Keychain.Legacy.InternetPassword.save("Test2", forAccount: account2, label: "Test", inKeychain: keychain)

        let queriedPasswords = try Keychain.Legacy.InternetPassword.queryItems(limit: 10, inKeychain: keychain)
        expect(queriedPasswords).toNot(beNil())
        expect(queriedPasswords).to(haveCount(2))
        expect(queriedPasswords?.map(\.password)).to(contain("Test1", "Test2"))
        expect(queriedPasswords?.map(\.account)).to(contain(account1, account2))
    }

    func testQueryItemsWithAttributes() throws {
        try Keychain.Legacy.InternetPassword.save("Test1", forAccount: account1, securityDomain: "securityDomain", label: "Test", inKeychain: keychain)
        try Keychain.Legacy.InternetPassword.save("Test2", forAccount: account1, server: "server", label: "Test", inKeychain: keychain)
        try Keychain.Legacy.InternetPassword.save("Test3", forAccount: account1, protocol: .HTTP, label: "Test", inKeychain: keychain)
        try Keychain.Legacy.InternetPassword.save("Test4", forAccount: account1, authenticationType: .HTTPBasic, label: "Test", inKeychain: keychain)
        try Keychain.Legacy.InternetPassword.save("Test5", forAccount: account1, port: 80, label: "Test", inKeychain: keychain)
        try Keychain.Legacy.InternetPassword.save("Test6", forAccount: account1, path: "path", label: "Test", inKeychain: keychain)

        let queriedPasswords1 = try Keychain.Legacy.InternetPassword.queryItems(securityDomain: "securityDomain", limit: 10, inKeychain: keychain)
        expect(queriedPasswords1?.map(\.password)) == ["Test1"]

        let queriedPasswords2 = try Keychain.Legacy.InternetPassword.queryItems(server: "server", limit: 10, inKeychain: keychain)
        expect(queriedPasswords2?.map(\.password)) == ["Test2"]

        let queriedPasswords3 = try Keychain.Legacy.InternetPassword.queryItems(protocol: .HTTP, limit: 10, inKeychain: keychain)
        expect(queriedPasswords3?.map(\.password)) == ["Test3"]

        let queriedPasswords4 = try Keychain.Legacy.InternetPassword.queryItems(authenticationType: .HTTPBasic, limit: 10, inKeychain: keychain)
        expect(queriedPasswords4?.map(\.password)) == ["Test4"]

        let queriedPasswords5 = try Keychain.Legacy.InternetPassword.queryItems(port: 80, limit: 10, inKeychain: keychain)
        expect(queriedPasswords5?.map(\.password)) == ["Test5"]

        let queriedPasswords6 = try Keychain.Legacy.InternetPassword.queryItems(path: "path", limit: 10, inKeychain: keychain)
        expect(queriedPasswords6?.map(\.password)) == ["Test6"]
    }

    func testDeletion() throws {
        try Keychain.Legacy.InternetPassword.save(password, forAccount: account1, label: "Test", inKeychain: keychain)

        let result1 = try Keychain.Legacy.InternetPassword.deleteItems(forAccount: account1, inKeychain: keychain)
        expect(result1) == true

        let result2 = try Keychain.Legacy.InternetPassword.deleteItems(forAccount: account1, inKeychain: keychain)
        expect(result2) == false
    }
}
#endif

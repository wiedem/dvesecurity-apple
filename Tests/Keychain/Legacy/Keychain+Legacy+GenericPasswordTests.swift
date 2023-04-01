// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import XCTest

#if os(macOS)
final class Keychain_Legacy_GenericPasswordTests: TestCaseLegacyKeychain {
    private let password = "Password-1234!äöü/"
    private let account1 = "GenericPasswordTest1"
    private let account2 = "GenericPasswordTest2"
    private let service = "com.diva-e.tests.GenericPasswordTests"

    override func tearDownWithError() throws {
        try Keychain.Legacy.GenericPassword.delete(forAccount: account1, service: service, inKeychain: keychain)
        try Keychain.Legacy.GenericPassword.delete(forAccount: account2, service: service, inKeychain: keychain)

        try super.tearDownWithError()
    }

    func testSaveAndQuery() throws {
        try Keychain.Legacy.GenericPassword.save(password, forAccount: account1, service: service, label: "Test", inKeychain: keychain)

        let queriedPassword = try Keychain.Legacy.GenericPassword.query(forAccount: account1, service: service, inKeychain: keychain)
        expect(queriedPassword) == password
    }

    func testSaveAndQueryMultipleItems() throws {
        try Keychain.Legacy.GenericPassword.save("Test1", forAccount: account1, service: service, label: "Test", inKeychain: keychain)
        try Keychain.Legacy.GenericPassword.save("Test2", forAccount: account2, service: service, label: "Test", inKeychain: keychain)

        let queriedPasswords = try Keychain.Legacy.GenericPassword.queryItems(limit: 10, inKeychain: keychain)
        expect(queriedPasswords).toNot(beNil())
        expect(queriedPasswords).to(haveCount(2))
        expect(queriedPasswords?.map(\.value).map({ String(data: $0, encoding: .utf8) })).to(contain("Test1", "Test2"))
        expect(queriedPasswords?.map(\.account)).to(contain(account1, account2))
    }

    func testQueryItemsWithAttributes() throws {
        try Keychain.Legacy.GenericPassword.save("Test1", forAccount: account1, service: "service1", label: "Test", inKeychain: keychain)
        try Keychain.Legacy.GenericPassword.save("Test2", forAccount: account2, service: "service2", label: "Test", inKeychain: keychain)
        try Keychain.Legacy.GenericPassword.save("Test3", forAccount: account1, service: "service2", label: "Test", inKeychain: keychain)

        let queriedPasswords1 = try Keychain.Legacy.GenericPassword.queryItems(account: account1, limit: 10, inKeychain: keychain)
        expect(queriedPasswords1).toNot(beNil())
        expect(queriedPasswords1).to(haveCount(2))
        expect(queriedPasswords1?.map(\.value).map({ String(data: $0, encoding: .utf8) })).to(contain("Test1", "Test3"))

        let queriedPasswords2 = try Keychain.Legacy.GenericPassword.queryItems(service: "service2", limit: 10, inKeychain: keychain)
        expect(queriedPasswords2).toNot(beNil())
        expect(queriedPasswords2).to(haveCount(2))
        expect(queriedPasswords2?.map(\.value).map({ String(data: $0, encoding: .utf8) })).to(contain("Test2", "Test3"))

        let queriedPasswords3 = try Keychain.Legacy.GenericPassword.queryItems(account: account2, service: "service2", limit: 10, inKeychain: keychain)
        expect(queriedPasswords3).toNot(beNil())
        expect(queriedPasswords3?.map(\.value).map({ String(data: $0, encoding: .utf8) })) == ["Test2"]
    }

    func testAttributesOfSavedItem() throws {
        try Keychain.Legacy.GenericPassword.save(password, forAccount: account1, service: service, label: "label", inKeychain: keychain)

        let items = try Keychain.Legacy.GenericPassword.queryItems(limit: 10, inKeychain: keychain)
        expect(items).to(haveCount(1))
        expect(items?.first?.value) == password.data(using: .utf8)!
        expect(items?.first?.account) == account1
        expect(items?.first?.service) == service
        expect(items?.first?.synchronizable) == false
        expect(items?.first?.label) == "label"
        expect(items?.first?.description).to(beNil())
        expect(items?.first?.comment).to(beNil())
        expect(items?.first?.creator).to(beNil())
    }

    func testAttributesOfSavedItemWithDefaults() throws {
        try Keychain.Legacy.GenericPassword.save(password, forAccount: account1, service: service, label: "", inKeychain: keychain)

        let items = try Keychain.Legacy.GenericPassword.queryItems(limit: 10, inKeychain: keychain)
        expect(items).to(haveCount(1))
        expect(items?.first?.value) == password.data(using: .utf8)!
        expect(items?.first?.account) == account1
        expect(items?.first?.service) == service
        expect(items?.first?.synchronizable) == false
        expect(items?.first?.label).to(beNil())
        expect(items?.first?.description).to(beNil())
        expect(items?.first?.comment).to(beNil())
        expect(items?.first?.creator).to(beNil())
    }

    func testDeletion() throws {
        try Keychain.Legacy.GenericPassword.save(password, forAccount: account1, service: service, label: "Test", inKeychain: keychain)

        let result1 = try Keychain.Legacy.GenericPassword.delete(forAccount: account1, service: service, inKeychain: keychain)
        expect(result1) == true

        let result2 = try Keychain.Legacy.GenericPassword.delete(forAccount: account1, service: service, inKeychain: keychain)
        expect(result2) == false
    }
}
#endif

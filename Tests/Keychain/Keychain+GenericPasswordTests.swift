// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import XCTest

class Keychain_GenericPasswordTests: XCTestCase {
    private static let configuredAccessGroups = Keychain.accessGroups

    private static let password = "Password-1234!äöü/"
    private static let account1 = "GenericPasswordTest1"
    private static let account2 = "GenericPasswordTest2"
    private static let service = "com.diva-e.tests.GenericPasswordTests"

    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .genericPassword, inAccessGroups: Self.configuredAccessGroups)
    }

    func testQueryWithoutResult() throws {
        expect(try self.queryPassword()).to(beNil())
    }

    func testSaveAndQuery() throws {
        try Keychain.GenericPassword.save(password, forAccount: account1, service: service)
        expect(try self.queryPassword()) == password
    }

    func testSaveAndQueryMultipleItems() throws {
        try Keychain.GenericPassword.save("Test1", forAccount: account1, service: service)
        try Keychain.GenericPassword.save("Test2", forAccount: account2, service: service)
        try Keychain.GenericPassword.saveSynchronizable("Test3", forAccount: account1, service: service)

        let items = try wait(description: "Keychain query") {
            Keychain.GenericPassword.queryItems(completion: $0)
        }
        expect(items).toNot(beNil())
        expect(items).to(haveCount(3))
        expect(items?.map(\.value).map({ String(data: $0, encoding: .utf8) })).to(contain("Test1", "Test2", "Test3"))
        expect(items?.map(\.account)).to(contain(account1, account2))
    }

    func testQueryItemsWithAttributes() throws {
        try Keychain.GenericPassword.save("Test1", forAccount: account1, service: "service1")
        try Keychain.GenericPassword.save("Test2", forAccount: account2, service: "service2")
        try Keychain.GenericPassword.save("Test3", forAccount: account1, service: "service2")

        let queriedPasswords1 = try Keychain.GenericPassword.queryItems(account: account1)
        expect(queriedPasswords1).toNot(beNil())
        expect(queriedPasswords1).to(haveCount(2))
        expect(queriedPasswords1?.map(\.value).map({ String(data: $0, encoding: .utf8) })).to(contain("Test1", "Test3"))

        let queriedPasswords2 = try Keychain.GenericPassword.queryItems(service: "service2")
        expect(queriedPasswords2).toNot(beNil())
        expect(queriedPasswords2).to(haveCount(2))
        expect(queriedPasswords2?.map(\.value).map({ String(data: $0, encoding: .utf8) })).to(contain("Test2", "Test3"))

        let queriedPasswords3 = try Keychain.GenericPassword.queryItems(account: account2, service: "service2")
        expect(queriedPasswords3).toNot(beNil())
        expect(queriedPasswords3?.map(\.value).map({ String(data: $0, encoding: .utf8) })) == ["Test2"]
    }

    func testAttributesOfSavedItem() throws {
        try Keychain.GenericPassword.save(password, forAccount: account1, service: service, label: "label")

        let items = try wait(description: "Keychain query") {
            Keychain.GenericPassword.queryItems(completion: $0)
        }
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
        try Keychain.GenericPassword.save(password, forAccount: account1, service: service)

        let items = try wait(description: "Keychain query") {
            Keychain.GenericPassword.queryItems(completion: $0)
        }
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

    func testSaveAndQueryKey() throws {
        let key = CustomKey(value: password)

        try Keychain.GenericPassword.saveKey(key, forAccount: account1, service: service)

        let queriedKey: CustomKey? = try wait(description: "Keychain query") {
            Keychain.GenericPassword.queryKey(forAccount: self.account1, service: self.service, completion: $0)
        }
        expect(queriedKey) == key
    }

    func testSavingWithUnconfiguredAccessGroup() {
        expect {
            try Keychain.GenericPassword.save(self.password, forAccount: self.account1, service: self.service, accessGroup: "UnknownAccessGroup")
        }.to(throwError {
            expect($0) == KeychainError.itemSavingFailed(status: errSecMissingEntitlement)
        })
    }

    func testSavingPasswordWithEqualAttributesTwice() throws {
        try Keychain.GenericPassword.save(password, forAccount: account1, service: service)
        expect {
            try Keychain.GenericPassword.save("CHANGED", forAccount: self.account1, service: self.service)
        }.to(throwError {
            expect($0) == KeychainError.itemSavingFailed(status: errSecDuplicateItem)
        })
    }

    func testUpdate() throws {
        try Keychain.GenericPassword.save(password, forAccount: account1, service: service)

        try Keychain.GenericPassword.update(newPassword: "CHANGED", forAccount: account1, service: service)

        let queriedPassword = try queryPassword()
        expect(queriedPassword) == "CHANGED"
    }

    func testUpsert() throws {
        try Keychain.GenericPassword.upsert(password, forAccount: account1, service: service)
        let queriedPassword1 = try queryPassword()
        expect(queriedPassword1) == password

        try Keychain.GenericPassword.upsert("CHANGED", forAccount: account1, service: service)

        let queriedPassword2 = try queryPassword()
        expect(queriedPassword2) == "CHANGED"
    }

    func testDeletion() throws {
        try Keychain.GenericPassword.save(password, forAccount: account1, service: service)

        let result1 = try Keychain.GenericPassword.delete(forAccount: account1, service: service)
        expect(result1) == true

        let result2 = try Keychain.GenericPassword.delete(forAccount: account1, service: service)
        expect(result2) == false
    }
}

// MARK: - Private
private extension Keychain_GenericPasswordTests {
    var password: String { Self.password }
    var account1: String { Self.account1 }
    var account2: String { Self.account2 }
    var service: String { Self.service }

    func queryPassword(account: String = account1, service: String = service, expectationDescription: String = "Keychain query") throws -> String? {
        try wait(description: expectationDescription) {
            Keychain.GenericPassword.query(forAccount: account, service: service, completion: $0)
        }
    }
}

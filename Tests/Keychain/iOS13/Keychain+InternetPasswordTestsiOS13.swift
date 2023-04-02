// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import LocalAuthentication
import Nimble
import XCTest

@available(iOS 13.0, *)
final class Keychain_InternetPasswordTestsiOS13: TestCaseiOS13 {
    private static let configuredAccessGroups = Keychain.accessGroups

    private let password = "Password-1234!äöü/"
    private let account1 = "InternetPasswordTest1"
    private let account2 = "InternetPasswordTest2"

    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .internetPassword, inAccessGroups: Self.configuredAccessGroups)
    }

    func testSaveAndQuery() throws {
        try Keychain.InternetPassword.save(password, forAccount: account1)

        let queriedPassword = try Keychain.InternetPassword.queryOne(forAccount: account1)
        expect(queriedPassword) == password
    }

    func testSaveAndQueryMultipleItems() throws {
        try Keychain.InternetPassword.save("Test1", forAccount: account1)
        try Keychain.InternetPassword.save("Test2", forAccount: account2)
        try Keychain.InternetPassword.saveSynchronizable("Test3", forAccount: account1)

        let items = try Keychain.InternetPassword.queryItems()
        expect(items).toNot(beNil())
        expect(items).to(haveCount(3))
        expect(items?.map(\.password)).to(contain("Test1", "Test2", "Test3"))
        expect(items?.map(\.account)).to(contain(account1, account2))
    }

    func testQueryOneWithAmbiguousResult() throws {
        try Keychain.InternetPassword.save(password, forAccount: account1, securityDomain: "domain1")
        try Keychain.InternetPassword.save(password, forAccount: account1, securityDomain: "domain2")

        expect {
            _ = try Keychain.InternetPassword.queryOne(forAccount: self.account1)
        }.to(throwError(KeychainError.ambiguousQueryResult))
    }

    func testQueriedAttributesOfSavedItem() throws {
        let securityDomain = "security domain"
        let server = "dvesecurity.test"
        let `protocol`: Keychain.InternetPassword.NetworkProtocol = .http
        let authenticationType: Keychain.InternetPassword.AuthenticationType = .httpBasic
        let port: UInt16 = 80
        let path = "test"

        try Keychain.InternetPassword.save(
            password,
            forAccount: account1,
            securityDomain: securityDomain,
            server: server,
            protocol: `protocol`,
            authenticationType: authenticationType,
            port: port,
            path: path
        )

        let items = try Keychain.InternetPassword.queryItems()
        expect(items).to(haveCount(1))
        expect(items?.first?.password) == password
        expect(items?.first?.account) == account1
        expect(items?.first?.securityDomain) == securityDomain
        expect(items?.first?.server) == server
        expect(items?.first?.protocol) == `protocol`
        expect(items?.first?.authenticationType) == authenticationType
        expect(items?.first?.port) == port
        expect(items?.first?.path) == path

        expect(items?.first?.synchronizable) == false
        expect(items?.first?.label).to(beNil())
        expect(items?.first?.description).to(beNil())
        expect(items?.first?.comment).to(beNil())
        expect(items?.first?.creator).to(beNil())
    }

    func testSaveUpdateDeletePasswordsWithAccessGroup() throws {
        try Keychain.InternetPassword.save("password1", forAccount: account1, accessGroup: Self.configuredAccessGroups[0])
        try Keychain.InternetPassword.save("password2", forAccount: account1, accessGroup: Self.configuredAccessGroups[1])

        let queriedPassword1 = try Keychain.InternetPassword.queryOne(forAccount: account1, accessGroup: Self.configuredAccessGroups[0])
        let queriedPassword2 = try Keychain.InternetPassword.queryOne(forAccount: account1, accessGroup: Self.configuredAccessGroups[1])
        expect(queriedPassword1) == "password1"
        expect(queriedPassword2) == "password2"

        try Keychain.InternetPassword.updateItems(newPassword: "changed-password1", forAccount: account1, accessGroup: Self.configuredAccessGroups[0])

        let queriedPassword1AfterUpdate = try Keychain.InternetPassword.queryOne(forAccount: account1, accessGroup: Self.configuredAccessGroups[0])
        let queriedPassword2AfterUpdate = try Keychain.InternetPassword.queryOne(forAccount: account1, accessGroup: Self.configuredAccessGroups[1])
        expect(queriedPassword1AfterUpdate) == "changed-password1"
        expect(queriedPassword2AfterUpdate) == "password2"

        try Keychain.InternetPassword.deleteItems(forAccount: account1, accessGroup: Self.configuredAccessGroups[1])

        let queriedPassword1AfterDeletion = try Keychain.InternetPassword.queryOne(forAccount: account1, accessGroup: Self.configuredAccessGroups[0])
        let queriedPassword2AfterDeletion = try Keychain.InternetPassword.queryOne(forAccount: account1, accessGroup: Self.configuredAccessGroups[1])
        expect(queriedPassword1AfterDeletion) == "changed-password1"
        expect(queriedPassword2AfterDeletion).to(beNil())
    }

    func testUpdateToDifferentAccessGroup() throws {
        try Keychain.InternetPassword.save(password, forAccount: account1)

        let queriedPassword = try Keychain.InternetPassword.queryOne(forAccount: account1)
        expect(queriedPassword) == password

        try Keychain.InternetPassword.updateItems(newPassword: "CHANGED", forAccount: account1, accessGroup: Self.configuredAccessGroups[0])

        let queriedPasswordAfterUpdate = try Keychain.InternetPassword.queryOne(forAccount: account1, accessGroup: Self.configuredAccessGroups[0])
        expect(queriedPasswordAfterUpdate) == "CHANGED"
    }

    func testSaveAndUpdate() throws {
        continueAfterFailure = false
        try Keychain.InternetPassword.save(password, forAccount: account1)
        let savedPassword = try Keychain.InternetPassword.queryOne(forAccount: account1)
        expect(savedPassword) == password

        try Keychain.InternetPassword.updateItems(newPassword: "\(password)-udpated", forAccount: account1)
        let updatedPassword = try Keychain.InternetPassword.queryOne(forAccount: account1)
        expect(updatedPassword) == "\(password)-udpated"
    }

    func testSaveQueryDifferentAccounts() throws {
        let testTuple1 = (account: "TestAccount1", password: "Password1")
        let testTuple2 = (account: "TestAccount2", password: "Password2")

        try Keychain.InternetPassword.save(testTuple1.password, forAccount: testTuple1.account)
        try Keychain.InternetPassword.save(testTuple2.password, forAccount: testTuple2.account)

        let queryPassword1 = try Keychain.InternetPassword.queryOne(forAccount: testTuple1.account)
        let queryPassword2 = try Keychain.InternetPassword.queryOne(forAccount: testTuple2.account)
        expect(queryPassword1) == testTuple1.password
        expect(queryPassword2) == testTuple2.password
    }

    func testUpsert() throws {
        continueAfterFailure = false
        try Keychain.InternetPassword.upsert("foo", forAccount: account1)
        let insertedPassword = try Keychain.InternetPassword.queryOne(forAccount: account1)
        expect(insertedPassword) == "foo"

        try Keychain.InternetPassword.upsert("bar", forAccount: account1)
        let updatedPassword = try Keychain.InternetPassword.queryOne(forAccount: account1)
        expect(updatedPassword) == "bar"
    }

    func testDelete() throws {
        continueAfterFailure = false
        try Keychain.InternetPassword.save(password, forAccount: account1)
        let passwordQuery = try Keychain.InternetPassword.queryOne(forAccount: account1)
        expect(passwordQuery) == password

        try Keychain.InternetPassword.deleteItems(forAccount: account1)
        let deletedPasswordQuery = try Keychain.InternetPassword.queryOne(forAccount: account1)
        expect(deletedPasswordQuery).to(beNil())
    }

    func testSaveWithProtectionClass() throws {
        for protectionClass in Keychain.ItemAccessibility.allCases {
            expect { () in
                try Keychain.InternetPassword.save(self.password, forAccount: self.account1, accessControl: Keychain.AccessControl(itemAccessibility: protectionClass))
                let queriedPassword = try Keychain.InternetPassword.queryOne(forAccount: self.account1)

                expect(queriedPassword).to(equal(self.password), description: "Failed for protectionClass: \(protectionClass)")
                try Keychain.deleteAllItems(ofClass: .internetPassword)
            }.toNot(throwError(), description: "Saving internet password with protection class '\(protectionClass)' failed with error.")
        }
    }
}

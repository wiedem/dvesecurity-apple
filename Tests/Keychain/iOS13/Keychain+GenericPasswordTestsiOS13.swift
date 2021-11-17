// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import LocalAuthentication
import Nimble
import XCTest

@available(iOS 13.0, *)
class Keychain_GenericPasswordTestsiOS13: TestCaseiOS13 {
    private static let configuredAccessGroups = Keychain.accessGroups

    private let password = "Password-1234!äöü/"
    private let account1 = "GenericPasswordTest1"
    private let account2 = "GenericPasswordTest2"
    private let service = "com.diva-e.tests.GenericPasswordTests"

    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .genericPassword, inAccessGroups: Self.configuredAccessGroups)
    }

    func testSaveAndQuery() throws {
        try Keychain.GenericPassword.save(password, forAccount: account1, service: service)

        let queriedPassword = try Keychain.GenericPassword.query(forAccount: account1, service: service)
        expect(queriedPassword) == password
    }

    func testSaveAndQueryKey() throws {
        let key = CustomKey(value: password)

        try Keychain.GenericPassword.saveKey(key, forAccount: account1, service: service)

        let queriedKey: CustomKey? = try Keychain.GenericPassword.queryKey(forAccount: account1, service: service)
        expect(queriedKey) == key
    }

    func testSaveAndQueryAll() throws {
        try Keychain.GenericPassword.save("Test1", forAccount: account1, service: service)
        try Keychain.GenericPassword.save("Test2", forAccount: account2, service: service)
        try Keychain.GenericPassword.saveSynchronizable("Test3", forAccount: account1, service: service)

        let items = try Keychain.GenericPassword.queryItems()
        expect(items).toNot(beNil())
        expect(items).to(haveCount(3))
        expect(items?.map(\.value).map({ String(data: $0, encoding: .utf8) })).to(contain("Test1", "Test2", "Test3"))
        expect(items?.map(\.account)).to(contain(account1, account2))
        expect(items?.map(\.service)).to(contain(service))
    }

    func testUpsert() throws {
        continueAfterFailure = false
        try Keychain.GenericPassword.upsert("foo", forAccount: account1, service: service)
        let insertedPassword = try Keychain.GenericPassword.query(forAccount: account1, service: service)
        expect(insertedPassword) == "foo"

        try Keychain.GenericPassword.upsert("bar", forAccount: account1, service: service)
        let updatedPassword = try Keychain.GenericPassword.query(forAccount: account1, service: service)
        expect(updatedPassword) == "bar"
    }

    func testDelete() throws {
        continueAfterFailure = false
        try Keychain.GenericPassword.save(password, forAccount: account1, service: service)
        let passwordQuery = try Keychain.GenericPassword.query(forAccount: account1, service: service)
        expect(passwordQuery) == password

        try Keychain.GenericPassword.delete(forAccount: account1, service: service)
        let deletedPasswordQuery = try Keychain.GenericPassword.query(forAccount: account1, service: service)
        expect(deletedPasswordQuery).to(beNil())
    }

    func testSaveUpdateDeletePasswordsWithAccessGroup() throws {
        try Keychain.GenericPassword.save("password1", forAccount: account1, service: service, accessGroup: Self.configuredAccessGroups[0])
        try Keychain.GenericPassword.save("password2", forAccount: account1, service: service, accessGroup: Self.configuredAccessGroups[1])

        let queriedPassword1 = try Keychain.GenericPassword.query(forAccount: account1, service: service, accessGroup: Self.configuredAccessGroups[0])
        let queriedPassword2 = try Keychain.GenericPassword.query(forAccount: account1, service: service, accessGroup: Self.configuredAccessGroups[1])
        expect(queriedPassword1) == "password1"
        expect(queriedPassword2) == "password2"

        try Keychain.GenericPassword.update(
            newPassword: "changed-password1",
            forAccount: account1,
            service: service,
            accessGroup: Self.configuredAccessGroups[0]
        )

        let queriedPassword1AfterUpdate = try Keychain.GenericPassword.query(
            forAccount: account1,
            service: service,
            accessGroup: Self.configuredAccessGroups[0]
        )
        let queriedPassword2AfterUpdate = try Keychain.GenericPassword.query(
            forAccount: account1,
            service: service,
            accessGroup: Self.configuredAccessGroups[1]
        )
        expect(queriedPassword1AfterUpdate) == "changed-password1"
        expect(queriedPassword2AfterUpdate) == "password2"

        try Keychain.GenericPassword.delete(forAccount: account1, service: service, accessGroup: Self.configuredAccessGroups[1])

        let queriedPassword1AfterDeletion = try Keychain.GenericPassword.query(
            forAccount: account1,
            service: service,
            accessGroup: Self.configuredAccessGroups[0]
        )
        let queriedPassword2AfterDeletion = try Keychain.GenericPassword.query(
            forAccount: account1,
            service: service,
            accessGroup: Self.configuredAccessGroups[1]
        )
        expect(queriedPassword1AfterDeletion) == "changed-password1"
        expect(queriedPassword2AfterDeletion).to(beNil())
    }

    func testUpdateToDifferentAccessGroup() throws {
        try Keychain.GenericPassword.save(password, forAccount: account1, service: service)

        let queriedPassword = try Keychain.GenericPassword.query(forAccount: account1, service: service, accessGroup: Self.configuredAccessGroups[0])
        expect(queriedPassword) == password

        expect {
            try Keychain.GenericPassword.update(
                newPassword: "CHANGED",
                forAccount: self.account1,
                service: self.service,
                accessGroup: Self.configuredAccessGroups[1]
            )
        }.to(throwError {
            expect($0) == KeychainError.itemUpdateFailed(status: errSecItemNotFound)
        })
    }

    func testSaveAndUpdate() throws {
        continueAfterFailure = false
        try Keychain.GenericPassword.save(password, forAccount: account1, service: service)
        let savedPassword = try Keychain.GenericPassword.query(forAccount: account1, service: service)
        expect(savedPassword) == password

        try Keychain.GenericPassword.update(newPassword: "\(password)-udpated", forAccount: account1, service: service)
        let updatedPassword = try Keychain.GenericPassword.query(forAccount: account1, service: service)
        expect(updatedPassword) == "\(password)-udpated"
    }

    func testSaveQueryDifferentAccounts() throws {
        let testTuple1 = (account: "TestAccount1", password: "Password1")
        let testTuple2 = (account: "TestAccount2", password: "Password2")

        try Keychain.GenericPassword.save(testTuple1.password, forAccount: testTuple1.account, service: service)
        try Keychain.GenericPassword.save(testTuple2.password, forAccount: testTuple2.account, service: service)

        let queryPassword1 = try Keychain.GenericPassword.query(forAccount: testTuple1.account, service: service)
        let queryPassword2 = try Keychain.GenericPassword.query(forAccount: testTuple2.account, service: service)
        expect(queryPassword1) == testTuple1.password
        expect(queryPassword2) == testTuple2.password
    }

    func testSaveQueryDeleteDifferentServices() throws {
        let testTuple1 = (password: "Password1", service: "TestService1")
        let testTuple2 = (password: "Password2", service: "TestService2")

        try Keychain.GenericPassword.save(testTuple1.password, forAccount: account1, service: testTuple1.service)
        try Keychain.GenericPassword.save(testTuple2.password, forAccount: account1, service: testTuple2.service)

        let queryPassword1 = try Keychain.GenericPassword.query(forAccount: account1, service: testTuple1.service)
        let queryPassword2 = try Keychain.GenericPassword.query(forAccount: account1, service: testTuple2.service)
        expect(queryPassword1) == testTuple1.password
        expect(queryPassword2) == testTuple2.password
    }

    func testSaveWithProtectionClass() throws {
        for protectionClass in Keychain.ItemAccessibility.allCases {
            expect { () -> Void in
                try Keychain.GenericPassword.save(
                    self.password,
                    forAccount: self.account1,
                    service: self.service,
                    accessControl: Keychain.AccessControl(itemAccessibility: protectionClass)
                )
                let queriedPassword = try Keychain.GenericPassword.query(forAccount: self.account1, service: self.service)

                expect(queriedPassword).to(equal(self.password), description: "Failed for protectionClass: \(protectionClass)")
                try Keychain.deleteAllItems(ofClass: .genericPassword)
            }.toNot(throwError(), description: "Saving generic password with protection class '\(protectionClass)' failed with error.")
        }
    }
}

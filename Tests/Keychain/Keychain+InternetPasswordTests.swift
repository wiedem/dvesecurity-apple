// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import XCTest

final class Keychain_InternetPasswordTests: XCTestCase {
    private static let configuredAccessGroups = Keychain.accessGroups

    private static let password = "Password-1234!äöü/"
    private static let account1 = "InternetPasswordTest1"
    private static let account2 = "InternetPasswordTest2"

    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .internetPassword)
    }

    func testQueryWithoutResult() throws {
        expect(try self.queryPassword()).to(beNil())
    }

    func testSaveAndQuery() throws {
        try Keychain.InternetPassword.save("Test1", forAccount: account1)
        expect(try self.queryPassword(account: self.account1)) == "Test1" // swiftformat:disable:this --redundantSelf

        try Keychain.InternetPassword.save("Test2", forAccount: account2, securityDomain: "securityDomain", port: 80)
        expect(try self.queryPassword(account: self.account2)) == "Test2" // swiftformat:disable:this --redundantSelf
        expect(try self.queryPassword(account: self.account2, securityDomain: "securityDomain", port: 80)) == "Test2" // swiftformat:disable:this --redundantSelf
        expect(try self.queryPassword(account: self.account2, securityDomain: "securityDomain", path: "")) == "Test2" // swiftformat:disable:this --redundantSelf
    }

    func testSaveAndQueryMultipleItems() throws {
        try Keychain.InternetPassword.save("Test1", forAccount: account1)
        try Keychain.InternetPassword.save("Test2", forAccount: account2, securityDomain: "securityDomain", port: 80)
        try Keychain.InternetPassword.saveSynchronizable("Test3", forAccount: account1)

        let items = try wait(description: "Keychain query") {
            Keychain.InternetPassword.queryItems(completion: $0)
        }
        expect(items).toNot(beNil())
        expect(items).to(haveCount(3))
        expect(items?.map(\.password)).to(contain("Test1", "Test2", "Test3"))
        expect(items?.map(\.account)).to(contain(account1, account2))
    }

    func testQueryItemsWithAttributes() throws {
        try Keychain.InternetPassword.save("Test1", forAccount: account1, securityDomain: "securityDomain")
        try Keychain.InternetPassword.save("Test2", forAccount: account1, server: "server")
        try Keychain.InternetPassword.save("Test3", forAccount: account1, protocol: .http)
        try Keychain.InternetPassword.save("Test4", forAccount: account1, authenticationType: .httpBasic)
        try Keychain.InternetPassword.save("Test5", forAccount: account1, port: 80)
        try Keychain.InternetPassword.save("Test6", forAccount: account1, path: "path")

        let queriedPasswords1 = try wait(description: "Keychain query") {
            Keychain.InternetPassword.queryItems(securityDomain: "securityDomain", completion: $0)
        }
        expect(queriedPasswords1?.map(\.password)) == ["Test1"]

        let queriedPasswords2 = try wait(description: "Keychain query") {
            Keychain.InternetPassword.queryItems(server: "server", completion: $0)
        }
        expect(queriedPasswords2?.map(\.password)) == ["Test2"]

        let queriedPasswords3 = try wait(description: "Keychain query") {
            Keychain.InternetPassword.queryItems(protocol: .http, completion: $0)
        }
        expect(queriedPasswords3?.map(\.password)) == ["Test3"]

        let queriedPasswords4 = try wait(description: "Keychain query") {
            Keychain.InternetPassword.queryItems(authenticationType: .httpBasic, completion: $0)
        }
        expect(queriedPasswords4?.map(\.password)) == ["Test4"]

        let queriedPasswords5 = try wait(description: "Keychain query") {
            Keychain.InternetPassword.queryItems(port: 80, completion: $0)
        }
        expect(queriedPasswords5?.map(\.password)) == ["Test5"]

        let queriedPasswords6 = try wait(description: "Keychain query") {
            Keychain.InternetPassword.queryItems(path: "path", completion: $0)
        }
        expect(queriedPasswords6?.map(\.password)) == ["Test6"]
    }

    func testQueryOneWithAmbiguousResult() throws {
        try Keychain.InternetPassword.save(password, forAccount: account1, securityDomain: "domain1")
        try Keychain.InternetPassword.save(password, forAccount: account1, securityDomain: "domain2")

        expect {
            try self.queryPassword(account: self.account1)
        }.to(throwError(KeychainError.ambiguousQueryResult))
    }

    func testAttributesOfSavedItem() throws {
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

        let items = try wait(description: "Keychain query") {
            Keychain.InternetPassword.queryItems(completion: $0)
        }
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

    func testAttributesOfSavedItemWithDefaults() throws {
        try Keychain.InternetPassword.save(password, forAccount: account1)

        let items = try wait(description: "Keychain query") {
            Keychain.InternetPassword.queryItems(completion: $0)
        }
        expect(items).to(haveCount(1))
        expect(items?.first?.password) == password
        expect(items?.first?.account) == account1
        expect(items?.first?.securityDomain) == ""
        expect(items?.first?.server) == ""
        expect(items?.first?.protocol).to(beNil())
        expect(items?.first?.authenticationType).to(beNil())
        expect(items?.first?.port) == 0
        expect(items?.first?.path) == ""

        expect(items?.first?.synchronizable) == false
        expect(items?.first?.label).to(beNil())
        expect(items?.first?.description).to(beNil())
        expect(items?.first?.comment).to(beNil())
        expect(items?.first?.creator).to(beNil())
    }

    func testOptionalAttributesOfSavedItem() throws {
        try Keychain.InternetPassword.save(password, forAccount: account1)

        let items = try wait(description: "Keychain query") {
            Keychain.InternetPassword.queryItems(completion: $0)
        }
        expect(items).to(haveCount(1))
        expect(items?.first?.password) == password
        expect(items?.first?.account) == account1
        expect(items?.first?.securityDomain) == ""
        expect(items?.first?.server) == ""
        expect(items?.first?.protocol).to(beNil())
        expect(items?.first?.authenticationType).to(beNil())
        expect(items?.first?.port) == 0
        expect(items?.first?.path) == ""

        expect(items?.first?.synchronizable) == false
        expect(items?.first?.label).to(beNil())
        expect(items?.first?.description).to(beNil())
        expect(items?.first?.comment).to(beNil())
        expect(items?.first?.creator).to(beNil())
    }

    func testSavingWithUnconfiguredAccessGroup() {
        expect {
            try Keychain.InternetPassword.save(self.password, forAccount: self.account1, accessGroup: "UnknownAccessGroup")
        }.to(throwError {
            expect($0) == KeychainError.itemSavingFailed(status: errSecMissingEntitlement)
        })
    }

    func testSaveDuplicateItem() throws {
        try Keychain.InternetPassword.save(password, forAccount: account1)
        expect { try Keychain.InternetPassword.save("CHANGED", forAccount: self.account1) }.to(throwError {
            expect($0) == KeychainError.itemSavingFailed(status: errSecDuplicateItem)
        })
    }

    func testUpdate() throws {
        try Keychain.InternetPassword.save(password, forAccount: account1)

        try Keychain.InternetPassword.updateItems(newPassword: "CHANGED", forAccount: account1)
        expect(try self.queryPassword()) == "CHANGED"
    }

    func testUpdateNonExisting() throws {
        expect { try Keychain.InternetPassword.updateItems(newPassword: "CHANGED", forAccount: self.account1) }.to(throwError {
            expect($0) == KeychainError.itemUpdateFailed(status: errSecItemNotFound)
        })
    }

    func testUpsert() throws {
        try Keychain.InternetPassword.upsert(password, forAccount: account1)
        expect(try self.queryPassword()) == password

        try Keychain.InternetPassword.upsert("CHANGED", forAccount: account1)
        expect(try self.queryPassword()) == "CHANGED"
    }

    func testDeletion() throws {
        try Keychain.InternetPassword.save(password, forAccount: account1)

        let result1 = try Keychain.InternetPassword.deleteItems(forAccount: account1)
        expect(result1) == true

        let result2 = try Keychain.InternetPassword.deleteItems(forAccount: account1)
        expect(result2) == false
    }

    func testDeleteNonExisting() throws {
        let result = try Keychain.InternetPassword.deleteItems(forAccount: account1)
        expect(result) == false
    }
}

// MARK: - Private
private extension Keychain_InternetPasswordTests {
    private var password: String { Self.password }
    private var account1: String { Self.account1 }
    private var account2: String { Self.account2 }

    func queryPassword(
        account: String = account1,
        securityDomain: String? = nil,
        server: String? = nil,
        protocol: Keychain.InternetPassword.NetworkProtocol? = nil,
        authenticationType: Keychain.InternetPassword.AuthenticationType? = nil,
        port: UInt16? = nil,
        path: String? = nil,
        expectationDescription: String = "Keychain query"
    ) throws -> String? {
        try wait(description: expectationDescription) {
            Keychain.InternetPassword.queryOne(
                forAccount: account,
                securityDomain: securityDomain,
                server: server,
                protocol: `protocol`,
                authenticationType: authenticationType,
                port: port,
                path: path,
                completion: $0
            )
        }
    }
}

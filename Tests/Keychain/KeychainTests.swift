// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import XCTest

class KeychainTests: XCTestCase {
    private static let configuredAccessGroups = Keychain.accessGroups

    private let account = "KeychainPasswordTest"
    private let service = "com.diva-e.tests.KeychainTests"

    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .genericPassword)
        try Keychain.deleteAllItems(ofClass: .internetPassword)
    }

    func testDeleteItemsOfClassShouldNotThrowErrorIfNoItemExists() {
        expect { try Keychain.deleteAllItems(ofClass: .genericPassword) }.toNot(throwError())
    }
}

@available(iOS 13.0, *)
extension KeychainTests {
    func testDefaultAccessGroup() throws {
        expect(Keychain.defaultAccessGroup) == Self.configuredAccessGroups.first

        // Save an entry without a specified access group and check if the keychain behavior is the same.
        let defaultAccessGroup = try KeychainTests.defaultAccessGroup()
        expect(Keychain.defaultAccessGroup) == defaultAccessGroup
    }

    func testDeleteItemsOfClass() throws {
        try Keychain.GenericPassword.save("GenericPassword", forAccount: account, service: service)
        try Keychain.InternetPassword.save("InternetPassword", forAccount: account)
        try Keychain.InternetPassword.saveSynchronizable("InternetPasswordSync", forAccount: account)

        try Keychain.deleteAllItems(ofClass: .genericPassword)

        let genericPasswordAfterDeletion = try Keychain.GenericPassword.query(forAccount: account, service: service)
        let internetPassword = try Keychain.InternetPassword.queryOne(forAccount: account)
        let synchronizedInternetPassword = try Keychain.InternetPassword.queryOneSynchronizable(forAccount: account)
        expect(genericPasswordAfterDeletion).to(beNil())
        expect(internetPassword) == "InternetPassword"
        expect(synchronizedInternetPassword) == "InternetPasswordSync"

        try Keychain.deleteAllItems(ofClass: .internetPassword)

        let internetPassword2: String? = try Keychain.InternetPassword.queryOne(forAccount: account)
        let synchronizedInternet2: String? = try Keychain.InternetPassword.queryOneSynchronizable(forAccount: account)
        expect(internetPassword2).to(beNil())
        expect(synchronizedInternet2).to(beNil())
    }

    func testDeleteItemFromAccessGroup() throws {
        try Keychain.GenericPassword.save("GenericPassword1", forAccount: "account1", service: service)

        let accessGroup = Self.configuredAccessGroups[1]
        try Keychain.GenericPassword.save("GenericPassword2", forAccount: "account2", service: service, accessGroup: accessGroup)

        try Keychain.deleteAllItems(ofClass: .genericPassword, inAccessGroup: accessGroup)

        let genericPassword1 = try Keychain.GenericPassword.query(forAccount: "account1", service: service)
        let genericPassword2 = try Keychain.GenericPassword.query(forAccount: "account2", service: service, accessGroup: accessGroup)

        expect(genericPassword1) == "GenericPassword1"
        expect(genericPassword2).to(beNil())
    }

    func testDeleteItemsByQuery() throws {
        try Keychain.GenericPassword.save("GenericPassword1", forAccount: "account1", service: service)
        try Keychain.GenericPassword.save("GenericPassword2", forAccount: "account2", service: service)

        let genericPassword1 = try Keychain.GenericPassword.query(forAccount: "account1", service: service)
        let genericPassword2 = try Keychain.GenericPassword.query(forAccount: "account2", service: service)
        expect(genericPassword1) == "GenericPassword1"
        expect(genericPassword2) == "GenericPassword2"

        let deleteAllGenericPasswordsQuery = [kSecClass: Keychain.ItemClass.genericPassword.secClassString]
        try Keychain.deleteItems(query: deleteAllGenericPasswordsQuery as [String: Any])

        let genericPasswordAfterDeletion = try Keychain.GenericPassword.query(forAccount: account, service: service)
        let internetPasswordAfterDeletion = try Keychain.GenericPassword.query(forAccount: account, service: service)
        expect(genericPasswordAfterDeletion).to(beNil())
        expect(internetPasswordAfterDeletion).to(beNil())
    }
}

// MARK: - Helper methods
private extension KeychainTests {
    static let _defaultAccessGroupTestService = "defaultGroupTest.2F837814-8FCA-4324-9437-AFBB95A6288E"

    struct KeychainTestError: Error {
        let underlyingError: Error?

        init() {
            underlyingError = nil
        }

        init(underlyingError: Error) {
            self.underlyingError = underlyingError
        }
    }

    @available(iOS 13.0, *)
    class func defaultAccessGroup() throws -> String {
        let itemAttributes: Set<Keychain.ItemAttribute> = [
            .service(_defaultAccessGroupTestService), .accessControl(.afterFirstUnlockThisDeviceOnly),
        ]

        do {
            let query = Keychain.AddItemQuery(itemClass: .genericPassword, valueData: Data(), attributes: itemAttributes)
            try Keychain.saveItem(query: query)
        } catch {
            throw KeychainTestError(underlyingError: error)
        }

        defer {
            do {
                let query = Keychain.DeleteItemsQuery(itemClass: .genericPassword, attributes: itemAttributes)
                try Keychain.deleteItems(query: query)
            } catch {
                NSLog("Error deleting keychain generic password item for default access group test: \(error)")
            }
        }

        let attributesQuery = Keychain.FetchItemsQuery(itemClass: .genericPassword, returnType: .attributes, attributes: itemAttributes)

        guard let attributes: [String: Any] = try Keychain.queryOneItem(query: attributesQuery),
              let accessGroup = attributes[kSecAttrAccessGroup as String] as? String
        else {
            throw KeychainTestError()
        }
        return accessGroup
    }
}

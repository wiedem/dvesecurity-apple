// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import XCTest

class Keychain_InternetPassword_SynchronizableTests: XCTestCase {
    private static let configuredAccessGroups = Keychain.accessGroups

    private static let password = "Password-1234!äöü/"
    private static let synchronizedPassword = "SynchronizedPassword-1234!äöü/"
    private static let account = "InternetPasswordTest"

    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .internetPassword)
    }

    func testSaveAndQuery() throws {
        try Keychain.InternetPassword.save(password, forAccount: account)
        try Keychain.InternetPassword.saveSynchronizable(synchronizedPassword, forAccount: account)

        let queriedPassword = try queryPassword(synchronizable: false)
        let queriedSynchronizedPassword = try queryPassword(synchronizable: true)

        expect(queriedPassword) == password
        expect(queriedSynchronizedPassword) == synchronizedPassword
    }

    func testSavingWithUnconfiguredAccessGroup() {
        expect {
            try Keychain.InternetPassword.saveSynchronizable(self.password, forAccount: self.account, accessGroup: "UnknownAccessGroup")
        }.to(throwError {
            expect($0) == KeychainError.itemSavingFailed(status: errSecMissingEntitlement)
        })
    }

    func testSavingPasswordWithEqualAttributesTwice() throws {
        try Keychain.InternetPassword.saveSynchronizable(password, forAccount: account)
        expect { try Keychain.InternetPassword.saveSynchronizable("CHANGED", forAccount: self.account) }.to(throwError {
            expect($0) == KeychainError.itemSavingFailed(status: errSecDuplicateItem)
        })
    }

    func testUpdate() throws {
        try Keychain.InternetPassword.save(password, forAccount: account)
        try Keychain.InternetPassword.saveSynchronizable(synchronizedPassword, forAccount: account)

        try Keychain.InternetPassword.updateSynchronizableItems(newPassword: "CHANGED", forAccount: account)

        expect(try self.queryPassword(synchronizable: false)) == password
        expect(try self.queryPassword(synchronizable: true)) == "CHANGED"
    }

    func testUpsert() throws {
        try Keychain.InternetPassword.upsertSynchronizable(password, forAccount: account)
        expect(try self.queryPassword(synchronizable: true)) == password

        try Keychain.InternetPassword.upsertSynchronizable("CHANGED", forAccount: account)
        expect(try self.queryPassword(synchronizable: true)) == "CHANGED"
    }

    func testDeletion() throws {
        try Keychain.InternetPassword.saveSynchronizable(password, forAccount: account)

        let result1 = try Keychain.InternetPassword.deleteSynchronizableItems(forAccount: account)
        expect(result1) == true

        let result2 = try Keychain.InternetPassword.deleteSynchronizableItems(forAccount: account)
        expect(result2) == false
    }

    func testDeletionWithSyncedAndUnsynced() throws {
        try Keychain.InternetPassword.save(password, forAccount: account)
        try Keychain.InternetPassword.saveSynchronizable(synchronizedPassword, forAccount: account)

        // Delete unsynced password and query both
        expect(try Keychain.InternetPassword.deleteItems(forAccount: self.account)) == true // swiftformat:disable:this --redundantSelf
        expect(try self.queryPassword(synchronizable: false))
            .to(beNil())
        expect(try self.queryPassword(synchronizable: true))
            == synchronizedPassword

        // Delete synced password and query both
        expect(try Keychain.InternetPassword.deleteSynchronizableItems(forAccount: self.account)) == true // swiftformat:disable:this --redundantSelf
        expect(try self.queryPassword(synchronizable: false))
            .to(beNil())
        expect(try self.queryPassword(synchronizable: true))
            .to(beNil())
    }
}

// MARK: - Private
private extension Keychain_InternetPassword_SynchronizableTests {
    private var password: String { Self.password }
    private var synchronizedPassword: String { Self.synchronizedPassword }
    private var account: String { Self.account }

    func queryPassword(synchronizable: Bool, account: String = account, expectationDescription: String = "Keychain query") throws -> String? {
        try wait(description: expectationDescription) {
            if synchronizable {
                Keychain.InternetPassword.queryOneSynchronizable(forAccount: account, completion: $0)
            } else {
                Keychain.InternetPassword.queryOne(forAccount: account, completion: $0)
            }
        }
    }
}

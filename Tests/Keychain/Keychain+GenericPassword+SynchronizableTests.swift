// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import XCTest

final class Keychain_GenericPassword_SynchronizableTests: XCTestCase {
    private static let configuredAccessGroups = Keychain.accessGroups

    private static let password = "Password-1234!äöü/"
    private static let synchronizedPassword = "SynchronizedePassword-1234!äöü/"
    private static let account = "GenericPasswordTest"
    private static let service = "com.diva-e.tests.GenericPasswordTests"

    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .genericPassword)
    }

    func testQueryWithoutResult() throws {
        let queriedPassword = try queryPassword(synchronizable: true)
        expect(queriedPassword).to(beNil())
    }

    func testSaveAndQuery() throws {
        try Keychain.GenericPassword.save(password, forAccount: account, service: service, accessControl: .init(itemAccessibility: .afterFirstUnlock))
        try Keychain.GenericPassword.saveSynchronizable(synchronizedPassword, forAccount: account, service: service, accessibility: .afterFirstUnlock)

        let queriedPassword = try queryPassword(synchronizable: false)
        let queriedSynchronizedPassword = try queryPassword(synchronizable: true)

        expect(queriedPassword) == password
        expect(queriedSynchronizedPassword) == synchronizedPassword
    }

    func testSaveAndQueryWithUnsafeData() throws {
        let key = Crypto.KeyData.createFromUnsafeData(password.data(using: .utf8)!)
        let synchronizedKey = Crypto.KeyData.createFromUnsafeData(synchronizedPassword.data(using: .utf8)!)

        try Keychain.GenericPassword.saveKey(key, forAccount: account, service: service)
        try Keychain.GenericPassword.saveSynchronizableKey(synchronizedKey, forAccount: account, service: service)

        let queriedKey: Crypto.KeyData? = try wait(description: "Keychain query") {
            Keychain.GenericPassword.queryKey(forAccount: account, service: service, completion: $0)
        }
        let queriedSynchronizedKey: Crypto.KeyData? = try wait(description: "Keychain query") {
            Keychain.GenericPassword.querySynchronizableKey(forAccount: account, service: service, completion: $0)
        }

        expect(queriedKey) == key
        expect(queriedSynchronizedKey) == synchronizedKey
    }

    func testSavingWithUnconfiguredAccessGroup() {
        expect {
            try Keychain.GenericPassword.saveSynchronizable(self.password, forAccount: self.account, service: self.service, accessGroup: "UnconfiguredAccessGroup")
        }.to(throwError {
            expect($0) == KeychainError.itemSavingFailed(status: errSecMissingEntitlement)
        })
    }

    func testSavingPasswordWithEqualAttributesTwice() throws {
        try Keychain.GenericPassword.saveSynchronizable(password, forAccount: account, service: service)
        expect {
            try Keychain.GenericPassword.saveSynchronizable("CHANGED", forAccount: self.account, service: self.service)
        }.to(throwError {
            expect($0) == KeychainError.itemSavingFailed(status: errSecDuplicateItem)
        })
    }

    func testUpdate() throws {
        try Keychain.GenericPassword.save(password, forAccount: account, service: service)
        try Keychain.GenericPassword.saveSynchronizable(synchronizedPassword, forAccount: account, service: service)

        try Keychain.GenericPassword.updateSynchronizable(newPassword: "CHANGED", forAccount: account, service: service)

        expect(try self.queryPassword(synchronizable: false)) == password
        expect(try self.queryPassword(synchronizable: true)) == "CHANGED"
    }

    func testUpsert() throws {
        try Keychain.GenericPassword.upsertSynchronizable(password, forAccount: account, service: service)
        expect(try self.queryPassword(synchronizable: true)) == password

        try Keychain.GenericPassword.upsertSynchronizable("CHANGED", forAccount: account, service: service)
        expect(try self.queryPassword(synchronizable: true)) == "CHANGED"
    }

    func testDeletion() throws {
        try Keychain.GenericPassword.saveSynchronizable(synchronizedPassword, forAccount: account, service: service)

        let result1 = try Keychain.GenericPassword.deleteSynchronizable(forAccount: account, service: service)
        expect(result1) == true
        let result2 = try Keychain.GenericPassword.deleteSynchronizable(forAccount: account, service: service)
        expect(result2) == false
    }

    func testDeletionWithSyncedAndUnsynced() throws {
        try Keychain.GenericPassword.save(password, forAccount: account, service: service)
        try Keychain.GenericPassword.saveSynchronizable(synchronizedPassword, forAccount: account, service: service)

        // Delete unsynced password and query both
        let result1 = try Keychain.GenericPassword.delete(forAccount: account, service: service)
        expect(result1) == true
        expect(try self.queryPassword(synchronizable: false)).to(beNil())
        expect(try self.queryPassword(synchronizable: true)) == synchronizedPassword

        // Delete synced password and query both
        let result2 = try Keychain.GenericPassword.deleteSynchronizable(forAccount: account, service: service)
        expect(result2) == true
        expect(try self.queryPassword(synchronizable: false)).to(beNil())
        expect(try self.queryPassword(synchronizable: true)).to(beNil())
    }
}

// MARK: - Private
private extension Keychain_GenericPassword_SynchronizableTests {
    private var password: String { Self.password }
    private var synchronizedPassword: String { Self.synchronizedPassword }
    private var account: String { Self.account }
    private var service: String { Self.service }

    func queryPassword(synchronizable: Bool, account: String = account, service: String = service, expectationDescription: String = "Keychain query") throws -> String? {
        try wait(description: expectationDescription) {
            if synchronizable {
                Keychain.GenericPassword.querySynchronizable(forAccount: account, service: service, completion: $0)
            } else {
                Keychain.GenericPassword.query(forAccount: account, service: service, completion: $0)
            }
        }
    }
}

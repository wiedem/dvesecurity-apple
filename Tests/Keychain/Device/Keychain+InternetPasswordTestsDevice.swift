// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import LocalAuthentication
import Nimble
import XCTest

class Keychain_InternetPasswordTestsDevice: TestCaseDevice {
    private let password = "Password-1234!äöü/"
    private let account = "InternetPasswordTest"

    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .internetPassword)
    }

    func testSaveAndQueryWithAuthenticationContextCredential() throws {
        let context = LAContext()
        context.setCredential("123".data(using: .utf8), type: .applicationPassword)

        let accessControl = Keychain.AccessControl(itemAccessibility: .afterFirstUnlock, flags: [.applicationPassword(prompt: nil)])
        try Keychain.InternetPassword.save(password, forAccount: account, accessControl: accessControl, authenticationContext: context)

        // Query with the same context.
        let queriedPassword1: String? = try wait(description: "Keychain query") {
            let queryAuthentication = Keychain.QueryAuthentication(authenticationContext: context, userInterface: .disallow)
            return Keychain.InternetPassword.queryOne(forAccount: self.account, authentication: queryAuthentication, completion: $0)
        }
        expect(queriedPassword1) == password

        // Query with a new context.
        let queriedPassword2: String? = try wait(description: "Keychain query") {
            let secondContext = LAContext()
            secondContext.setCredential("123".data(using: .utf8), type: .applicationPassword)
            let queryAuthentication = Keychain.QueryAuthentication(authenticationContext: secondContext, userInterface: .disallow)
            return Keychain.InternetPassword.queryOne(forAccount: self.account, authentication: queryAuthentication, completion: $0)
        }
        expect(queriedPassword2) == password
    }

    func testSaveAndQueryWithInvalidAuthenticationContextCredential() throws {
        let context = LAContext()
        context.setCredential("123".data(using: .utf8), type: .applicationPassword)

        let accessControl = Keychain.AccessControl(itemAccessibility: .afterFirstUnlock, flags: [.applicationPassword(prompt: nil)])
        try Keychain.InternetPassword.save(password, forAccount: account, accessControl: accessControl, authenticationContext: context)

        // Query with an invalid LAContext.
        expect {
            let _: String? = try self.wait(description: "Keychain query") {
                let invalidContext = LAContext()
                let queryAuthentication = Keychain.QueryAuthentication(authenticationContext: invalidContext, userInterface: .disallow)
                return Keychain.InternetPassword.queryOne(forAccount: self.account, authentication: queryAuthentication, completion: $0)
            }
        }.to(throwError {
            expect($0) == KeychainError.itemQueryFailed(status: errSecInteractionNotAllowed)
        })
    }
}

// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import LocalAuthentication
import Nimble
import XCTest

class Keychain_GenericPasswordTestsDevice: InteractiveTestCaseDevice {
    private let password = "Password-1234!äöü/"
    private let account = "GenericPasswordTest"
    private let service = "com.diva-e.tests.GenericPasswordTests"

    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .genericPassword)
    }

    func testQueryWithApplicationPassword() throws {
        let accessControl = Keychain.AccessControl(
            itemAccessibility: .afterFirstUnlockThisDeviceOnly,
            flags: [.applicationPassword(prompt: "Specify a password for the protected access to the keychain")]
        )

        try Keychain.GenericPassword.save(password, forAccount: account, service: service, accessControl: accessControl)
        // Manual confirmation is necessary for this test because we can't know if the user entered the proper password or if the authentication UI did appear properly.

        let authentication = Keychain.QueryAuthentication(userInterface: .allow(prompt: "Password for the protected Access to the Keychain Item"))

        _ = try wait(description: "Keychain query", timeout: Self.defaultUIInteractionTimeout) {
            Keychain.GenericPassword.query(forAccount: self.account, service: self.service, authentication: authentication, completion: $0)
        }
    }

    func testAccessControlFlagBiometryCurrentSet() throws {
        testViewModel.stopActivity()
        testViewModel.setTestTitle("Test access protection with current set biometry")
        testViewModel.addTestDescription("1. Make sure Biometry is currently active")

        let accessControl = Keychain.AccessControl(itemAccessibility: .afterFirstUnlockThisDeviceOnly, flags: [.biometryCurrentSet])

        let result1 = wait(expectationDescription: "Keychain save", timeout: Self.defaultUIInteractionTimeout) { expectation in
            self.testViewModel.addTestAction("2. Save Password") {
                defer { expectation?.fulfill() }

                do {
                    try Keychain.GenericPassword.save(self.password, forAccount: self.account, service: self.service, accessControl: accessControl)
                } catch {
                    fail("Failed to save password: \(error)")
                }
            }
        }
        guard result1.isCompleted else { return }

        testViewModel.removeLastTestSteps(3)

        // Second part: query the password which should return nil.
        let queriedPassword: String? = try wait(description: "Keychain query", timeout: Self.defaultUIInteractionTimeout) { completion in
            self.testViewModel.addTestDescription("1. Change the Biometrics")
            self.testViewModel.addTestAction("2. Query the Password") {
                Keychain.GenericPassword.query(forAccount: self.account, service: self.service, completion: completion)
            }
        }
        expect(queriedPassword).to(beNil())

        testViewModel.removeLastTestSteps(2)

        // Third part: try to save the password again.
        let result3 = wait(expectationDescription: "Keychain save", timeout: Self.defaultUIInteractionTimeout) { expectation in
            self.testViewModel.addTestDescription("Saving the Password again should not result in an error.")
            self.testViewModel.addTestAction("Save the Password again") {
                defer { expectation?.fulfill() }

                do {
                    try Keychain.GenericPassword.save(self.password, forAccount: self.account, service: self.service, accessControl: accessControl)
                } catch {
                    fail("Failed to save password: \(error)")
                }
            }
        }
        guard result3.isCompleted else { return }
    }

    func testAccessControlFlagBiometryCurrentSetWithLAContext() throws {
        testViewModel.stopActivity()
        testViewModel.setTestTitle("Test access protection with current set biometry and LAContext")

        let accessControl = Keychain.AccessControl(itemAccessibility: .afterFirstUnlockThisDeviceOnly, flags: [.biometryCurrentSet])
        let authenticationContext = LAContext()

        // Step 1: Evaluate the access control.
        testViewModel.addTestDescription("1. Make sure biometry is currently active")
        _ = try wait(description: "Policy evaluation", timeout: Self.defaultUIInteractionTimeout) { completion in
            self.testViewModel.addTestAction("2. Evaluate Access Control") {
                authenticationContext.evaluateAccessControl(accessControl,
                                                            operation: .useItem,
                                                            localizedReason: "Test access to protected keychain item",
                                                            reply: completion)
            }
        }

        testViewModel.removeLastTestSteps(2)

        // Step 2: Save the password.
        let result2 = wait(expectationDescription: "Keychain save", timeout: Self.defaultUIInteractionTimeout) { expectation in
            self.testViewModel.addTestAction("Save a new Password in the Keychain") {
                defer { expectation?.fulfill() }

                do {
                    try Keychain.GenericPassword.save(
                        self.password,
                        forAccount: self.account,
                        service: self.service,
                        accessControl: accessControl,
                        authenticationContext: authenticationContext
                    )
                } catch {
                    fail("Failed to save password: \(error)")
                }
            }
        }
        guard result2.isCompleted else { return }

        testViewModel.removeLastTestSteps(1)

        // Step 3: query the password which should return nil since the biometrics have changed.
        let queryAuthentication = Keychain.QueryAuthentication(userInterface: .disallow)

        let queriedPassword: String? = try wait(description: "Keychain query", timeout: Self.defaultUIInteractionTimeout) { completion in
            self.testViewModel.addTestDescription("1. Change the Biometrics")
            self.testViewModel.addTestAction("2. Query the Password") {
                Keychain.GenericPassword.query(forAccount: self.account, service: self.service, authentication: queryAuthentication, completion: completion)
            }
        }
        expect(queriedPassword).to(beNil())

        testViewModel.removeLastTestSteps(2)

        // Step 4: try to save the password again.
        let result4 = wait(expectationDescription: "Keychain save", timeout: Self.defaultUIInteractionTimeout) { expectation in
            self.testViewModel.addTestDescription("Saving the password again should not result in an error.")
            self.testViewModel.addTestAction("Save the password again") {
                defer { expectation?.fulfill() }

                do {
                    try Keychain.GenericPassword.save(self.password, forAccount: self.account, service: self.service, accessControl: accessControl)
                } catch {
                    fail("Failed to save password: \(error)")
                }
            }
        }
        guard result4.isCompleted else { return }
    }
}

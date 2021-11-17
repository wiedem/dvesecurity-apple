// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import LocalAuthentication
import Nimble
import XCTest

class Keychain_RSATestsiOSDevice: InteractiveTestCaseDevice {
    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .key)
    }

    func testSaveAndQueryWithApplicationPassword() throws {
        let accessControl = Keychain.AccessControl(
            itemAccessibility: .afterFirstUnlockThisDeviceOnly,
            flags: [.applicationPassword(prompt: "Specify a password for the protected access to the keychain")]
        )

        let privateKey = try Crypto.RSA.PrivateKey(bitCount: 2048)
        let keyTag = "Test Tag \(#function)"

        try Keychain.saveKey(privateKey, withTag: keyTag, accessControl: accessControl)

        // Manual confirmation is necessary for this test because we can't know if the user entered the proper password or if the authentication UI did appear properly.
        var queryResult: Result<Crypto.RSA.PrivateKey?, Error>?

        let result = wait(expectationDescription: "Keychain query", timeout: Self.defaultUIInteractionTimeout) { expectation in
            let authentication = Keychain.QueryAuthentication(userInterface: .allow(prompt: "Password for the protected access to the keychain item"))
            Keychain.queryKey(withTag: keyTag, authentication: authentication) { (result: Result<Crypto.RSA.PrivateKey?, Error>) in
                defer { expectation?.fulfill() }
                queryResult = result
            }
        }
        guard result.isCompleted else { return }

        switch queryResult {
        case let .success(queriedKey):
            expect(queriedKey?.pkcs1Representation) == privateKey.pkcs1Representation
        case let .failure(error):
            fail("Failed to query key: \(error)")
        default:
            break
        }
    }

    func testImplicitSaveAndQueryWithApplicationPassword() throws {
        let accessControl = Keychain.AccessControl(
            itemAccessibility: .afterFirstUnlockThisDeviceOnly,
            flags: [.applicationPassword(prompt: "Specify a password for the protected access to the keychain")]
        )

        let keyTag = "Test Tag \(#function)"
        let privateKey = try Crypto.RSA.PrivateKey(bitCount: 2048, inKeychainWithTag: keyTag, accessControl: accessControl)

        // Manual confirmation is necessary for this test because we can't know if the user entered the proper password or if the authentication UI did appear properly.
        var queryResult: Result<Crypto.RSA.PrivateKey?, Error>?

        let result = wait(expectationDescription: "Keychain query", timeout: Self.defaultUIInteractionTimeout) { expectation in
            let authentication = Keychain.QueryAuthentication(userInterface: .allow(prompt: "Password for the protected access to the keychain item"))
            Keychain.queryKey(withTag: keyTag, authentication: authentication) { (result: Result<Crypto.RSA.PrivateKey?, Error>) in
                defer { expectation?.fulfill() }
                queryResult = result
            }
        }
        guard result.isCompleted else { return }

        switch queryResult {
        case let .success(queriedKey):
            expect(queriedKey?.pkcs1Representation) == privateKey.pkcs1Representation
        case let .failure(error):
            fail("Failed to query key: \(error)")
        default:
            break
        }
    }

    func testAccessControlFlagBiometryCurrentSet() throws {
        testViewModel.stopActivity()
        testViewModel.setTestTitle("Test access protection with current set biometry")

        let keyTag = "Test Tag \(#function)"
        let accessControl = Keychain.AccessControl(itemAccessibility: .afterFirstUnlockThisDeviceOnly, flags: [.biometryCurrentSet])

        var privateKey: Crypto.RSA.PrivateKey!

        // Step 1: Generate and save a private key.
        testViewModel.addTestDescription("1. Make sure Biometry is currently active")
        let result1 = wait(expectationDescription: "Keychain save", timeout: Self.defaultUIInteractionTimeout) { expectation in
            self.testViewModel.addTestAction("2. Generate and save Private Key") {
                defer { expectation?.fulfill() }

                do {
                    privateKey = try Crypto.RSA.PrivateKey(bitCount: 2048, inKeychainWithTag: keyTag, accessControl: accessControl)
                } catch {
                    fail("Failed to save private key: \(error)")
                }
            }
        }
        testViewModel.removeLastTestSteps(2)
        guard result1.isCompleted else { return }

        // Step 2: query the private key which should return nil.
        var queryResult: Result<Crypto.RSA.PrivateKey?, Error>?
        let result2 = wait(expectationDescription: "Keychain query", timeout: Self.longUIInteractionTimeout) { expectation in
            self.testViewModel.addTestDescription("1. Change the Biometrics")
            self.testViewModel.addTestAction("2. Query the Private Key") {
                Keychain.queryKey(withTag: keyTag) { (result: Result<Crypto.RSA.PrivateKey?, Error>) in
                    queryResult = result
                    expectation?.fulfill()
                }
            }
        }
        testViewModel.removeLastTestSteps(2)
        guard result2.isCompleted else { return }

        switch queryResult {
        case let .success(queriedKey):
            expect(queriedKey).to(beNil())
        case let .failure(error):
            throw error
        default:
            break
        }

        // Step 3: try to save the private key again.
        let result3 = wait(expectationDescription: "Keychain save", timeout: Self.longUIInteractionTimeout) { expectation in
            self.testViewModel.addTestDescription("Saving the Private Key again should not result in an error.")
            self.testViewModel.addTestAction("Save the Private Key again") {
                defer { expectation?.fulfill() }

                do {
                    try Keychain.saveKey(privateKey, withTag: keyTag, accessControl: accessControl)
                } catch {
                    fail("Failed to save private key: \(error)")
                }
            }
        }
        guard result3.isCompleted else { return }
    }

    // swiftlint:disable:next cyclomatic_complexity
    func testAccessControlFlagBiometryCurrentSetWithLAContext() throws {
        testViewModel.stopActivity()
        testViewModel.setTestTitle("Test access protection with current set biometry")

        let keyTag = "Test Tag \(#function)"
        let accessControl = Keychain.AccessControl(itemAccessibility: .afterFirstUnlockThisDeviceOnly, flags: [.biometryCurrentSet])
        let authenticationContext = LAContext()

        // Step 1: Evaluate the access control.
        var evaluateAccessControlResult: Result<Void, Error>!

        testViewModel.addTestDescription("1. Make sure biometry is currently active")
        let result1 = wait(expectationDescription: "Policy evaluation", timeout: Self.longUIInteractionTimeout) { expectation in
            self.testViewModel.addTestAction("2. Evaluate Access Control") {
                authenticationContext
                    .evaluateAccessControl(accessControl, operation: .useItem, localizedReason: "Test access to protected keychain item") { result in
                        evaluateAccessControlResult = result
                        expectation?.fulfill()
                    }
            }
        }
        testViewModel.removeLastTestSteps(2)
        guard result1.isCompleted else { return }

        switch evaluateAccessControlResult {
        case let .failure(error):
            throw error
        default:
            break
        }

        // Step 2: Generate and save a private key.
        var privateKey: Crypto.RSA.PrivateKey!
        let result2 = wait(expectationDescription: "Private key generation", timeout: Self.longUIInteractionTimeout) { expectation in
            self.testViewModel.addTestAction("2. Generate and save Private Key") {
                defer { expectation?.fulfill() }

                do {
                    privateKey = try Crypto.RSA.PrivateKey(
                        bitCount: 2048,
                        inKeychainWithTag: keyTag,
                        accessControl: accessControl,
                        authenticationContext: authenticationContext
                    )
                } catch {
                    fail("Failed to save private key: \(error)")
                }
            }
        }
        testViewModel.removeLastTestSteps(3)
        guard result2.isCompleted else { return }

        // Step 3: query the private key which should return nil since the biometrics have changed.
        let queryAuthentication = Keychain.QueryAuthentication(userInterface: .disallow)

        var queryResult: Result<Crypto.RSA.PrivateKey?, Error>?
        let result3 = wait(expectationDescription: "Keychain query", timeout: Self.longUIInteractionTimeout) { expectation in
            self.testViewModel.addTestDescription("1. Change the Biometrics")
            self.testViewModel.addTestAction("2. Query the Private Key") {
                Keychain.queryKey(withTag: keyTag, authentication: queryAuthentication) { (result: Result<Crypto.RSA.PrivateKey?, Error>) in
                    queryResult = result
                    expectation?.fulfill()
                }
            }
        }
        testViewModel.removeLastTestSteps(2)
        guard result3.isCompleted else { return }

        switch queryResult {
        case let .success(queriedKey):
            expect(queriedKey).to(beNil())
        case let .failure(error):
            throw error
        default:
            break
        }

        // Step 4: try to save the private key again.
        let result4 = wait(expectationDescription: "Keychain save", timeout: Self.longUIInteractionTimeout) { expectation in
            self.testViewModel.addTestDescription("Saving the Private Key again should not result in an error.")
            self.testViewModel.addTestAction("Save the Private Key again") {
                defer { expectation?.fulfill() }

                do {
                    try Keychain.saveKey(privateKey, withTag: keyTag, accessControl: accessControl)
                } catch {
                    fail("Failed to save private key: \(error)")
                }
            }
        }
        guard result4.isCompleted else { return }
    }
}

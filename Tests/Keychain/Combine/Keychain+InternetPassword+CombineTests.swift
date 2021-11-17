// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
#if canImport(Combine)
import Nimble
import XCTest

@available(iOS 13.0, *)
class Keychain_InternetPassword_CombineTests: TestCaseCombine {
    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .internetPassword)
    }

    func testDeferredSaveAndQueryPublisher() throws {
        let password = "Password-1234!äöü/"
        let account1 = "InternetPasswordTest"

        var resultValue: String?
        var errorResult: Error?

        let result = wait(expectationDescription: "Keychain save and query", timeout: Self.defaultUIInteractionTimeout) { expectation in
            _ = Keychain
                .InternetPassword
                .savePublisher(for: password, account: account1)
                .flatMap { $0.queryOnePublisher(forAccount: account1) }
                .subscribe(on: DispatchQueue.global())
                .receive(on: RunLoop.main)
                .sink(receiveCompletion: { completion in
                    defer { expectation?.fulfill() }
                    if case let .failure(error) = completion {
                        errorResult = error
                    }
                }, receiveValue: { resultValue = $0 })
        }
        guard result.isCompleted else { return }

        expect(resultValue) == password
        expect(errorResult).to(beNil())
    }

    func testDeferredSaveAndQuerySynchronizablePublisher() throws {
        let password = "Password-1234!äöü/"
        let account1 = "InternetPasswordTest"

        var resultValue: String?
        var errorResult: Error?

        let result = wait(expectationDescription: "Keychain save and query", timeout: Self.defaultUIInteractionTimeout) { expectation in
            _ = Keychain
                .InternetPassword
                .saveSynchronizablePublisher(for: password, account: account1)
                .flatMap { $0.queryOneSynchronizablePublisher(forAccount: account1) }
                .subscribe(on: DispatchQueue.global())
                .receive(on: RunLoop.main)
                .sink(receiveCompletion: { completion in
                    defer { expectation?.fulfill() }
                    if case let .failure(error) = completion {
                        errorResult = error
                    }
                }, receiveValue: { resultValue = $0 })
        }
        guard result.isCompleted else { return }

        expect(resultValue) == password
        expect(errorResult).to(beNil())
    }
}
#endif

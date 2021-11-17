// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
#if canImport(Combine)
import Nimble
import XCTest

@available(iOS 13.0, *)
class Keychain_GenericPassword_CombineTests: TestCaseCombine {
    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .genericPassword)
    }

    func testDeferredSaveAndQueryPublisher() throws {
        let password = "Password-1234!äöü/"
        let account1 = "GenericPasswordTest"
        let service = "com.diva-e.tests.GenericPasswordTests"

        var resultValue: String?
        var errorResult: Error?

        let result = wait(expectationDescription: "Keychain save and query", timeout: Self.defaultUIInteractionTimeout) { expectation in
            _ = Keychain
                .GenericPassword
                .savePublisher(for: password, account: account1, service: service)
                .flatMap { $0.queryPublisher(forAccount: account1, service: service) }
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
        let account1 = "GenericPasswordTest"
        let service = "com.diva-e.tests.GenericPasswordTests"

        var resultValue: String?
        var errorResult: Error?

        let result = wait(expectationDescription: "Keychain save and query", timeout: Self.defaultUIInteractionTimeout) { expectation in
            _ = Keychain
                .GenericPassword
                .saveSynchronizablePublisher(for: password, account: account1, service: service)
                .flatMap { $0.querySynchronizablePublisher(forAccount: account1, service: service) }
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

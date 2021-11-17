// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
#if canImport(Combine)
import Nimble
import XCTest

@available(iOS 13.0, *)
class Keychain_AES_CombineTests: TestCaseCombine {
    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .key)
    }

    func testDeferredSaveAndQueryPublisher() throws {
        let keyTag = "Test Tag \(#function)"
        let applicationLabel = "appLabel".data(using: .utf8)!

        let key: Crypto.AES.Key = try Crypto.AES.Key(keySize: Crypto.AES.KeySize.bits256,
                                                     password: "Hello Test!",
                                                     withSalt: "Salt",
                                                     pseudoRandomAlgorithm: .hmacAlgSHA256,
                                                     rounds: 1)

        var queriedKey: Crypto.AES.Key?
        var errorResult: Error?

        let result = wait(expectationDescription: "Keychain save and query", timeout: Self.defaultUIInteractionTimeout) { expectation in
            _ = Keychain
                .saveKeyPublisher(for: key, withTag: keyTag, applicationLabel: applicationLabel)
                .flatMap { $0.queryKeyPublisher(withTag: keyTag, applicationLabel: applicationLabel) }
                .subscribe(on: DispatchQueue.global())
                .receive(on: RunLoop.main)
                .sink(receiveCompletion: { completion in
                    defer { expectation?.fulfill() }
                    if case let .failure(error) = completion {
                        errorResult = error
                    }
                }, receiveValue: { queriedKey = $0 })
        }
        guard result.isCompleted else { return }

        expect(queriedKey) == key
        expect(errorResult).to(beNil())
    }
}
#endif

// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
#if canImport(Combine)
import Nimble
import XCTest

@available(iOS 13.0, *)
class Keychain_RSA_CombineTests: TestCaseCombine {
    override func tearDownWithError() throws {
        try super.tearDownWithError()

        try Keychain.deleteAllItems(ofClass: .key)
    }

    func testDeferredSaveAndQueryPublisher() throws {
        let keyTag = "Test Tag \(#function)"

        let privateKey = try Crypto.RSA.PrivateKey(bitCount: 2048)
        let publicKey = privateKey.publicKey()

        var resultValue: Crypto.RSA.PrivateKey?
        var errorResult: Error?

        let result = wait(expectationDescription: "Keychain save and query", timeout: Self.defaultUIInteractionTimeout) { expectation in
            _ = Keychain
                .saveKeyPublisher(for: privateKey, withTag: keyTag)
                .flatMap { $0.queryKeyPublisher(for: publicKey, withTag: keyTag) }
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

        expect(resultValue?.pkcs1Representation) == privateKey.pkcs1Representation
        expect(errorResult).to(beNil())
    }
}
#endif

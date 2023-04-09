// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
#if canImport(Combine)
import Combine
import Nimble
import XCTest

@available(iOS 13.0, *)
final class Crypto_AES_CombineTests: TestCaseCombine {
    func testDeferredEncryptionAndDecryption() {
        let plainText = "Hello World!"
        let plainTextData = plainText.data(using: .utf8)!
        let password = "Password"
        let salt = "Salt"

        var resultValue: String?
        var errorResult: Error?

        _ = Crypto.AES
            .createInitVectorPublisher()
            .tryMap {
                let key = try Crypto.AES.Key(
                    keySize: .bits192,
                    password: password,
                    withSalt: salt,
                    pseudoRandomAlgorithm: .hmacAlgSHA256,
                    rounds: 1
                )
                return (key, $0)
            }
            .flatMap {
                let (key, initVector) = $0
                return key.encryptPublisher(for: plainTextData, initVector: initVector)
                    .map { (key, initVector, $0) }
                    .eraseToAnyPublisher()
            }
            .flatMap { arguments -> AnyPublisher<Data, Error> in
                let (key, initVector, cipherTextData) = arguments
                return key.decryptPublisher(for: cipherTextData, initVector: initVector)
            }
            .map { cipherTextData in
                String(data: cipherTextData, encoding: .utf8)!
            }
            .sink(
                receiveCompletion: { completion in
                    if case let .failure(error) = completion {
                        errorResult = error
                    }
                },
                receiveValue: { resultValue = $0 }
            )

        expect(resultValue) == plainText
        expect(errorResult).to(beNil())
    }
}
#endif

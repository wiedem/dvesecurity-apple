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

        _ = Crypto
            .AES
            .createIVPublisher()
            .tryMap { ivData -> (Crypto.AES.Key, Data) in
                let key = try Crypto.AES.Key(keySize: .bits192,
                                             password: password,
                                             withSalt: salt,
                                             pseudoRandomAlgorithm: .hmacAlgSHA256,
                                             rounds: 1)
                return (key, ivData)
            }.flatMap { arguments -> AnyPublisher<(Crypto.AES.Key, Data, Data), Error> in
                let (key, ivData) = arguments
                return key.encryptPublisher(for: plainTextData, ivData: ivData)
                    .map { (key, ivData, $0) }
                    .eraseToAnyPublisher()
            }.flatMap { arguments -> AnyPublisher<Data, Error> in
                let (key, ivData, cipherTextData) = arguments
                return key.decryptPublisher(for: cipherTextData, ivData: ivData)
            }.map { cipherTextData in
                String(data: cipherTextData, encoding: .utf8)!
            }
            .sink(receiveCompletion: { completion in
                if case let .failure(error) = completion {
                    errorResult = error
                }
            }, receiveValue: { resultValue = $0 })

        expect(resultValue) == plainText
        expect(errorResult).to(beNil())
    }
}
#endif

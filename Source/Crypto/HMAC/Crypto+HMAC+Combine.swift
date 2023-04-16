// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
#if canImport(Combine)
import Combine

public extension Crypto.HMAC {
    /// Returns a publisher that computes a message authentication code for the given data.
    ///
    /// - Parameters:
    ///   - data: The data for which to compute the authentication code.
    ///   - keyData: The symmetric key data used to secure the computation.
    static func authenticationCodePublisher(
        for data: some DataProtocol,
        keyData: some SecureData
    ) -> AnyPublisher<Data, Never> {
        Future { promise in
            let code = authenticationCode(for: data, keyData: keyData)
            promise(.success(code))
        }
        .eraseToAnyPublisher()
    }

    /// Returns a publisher that checks whether the given code is valid for a block of data.
    ///
    /// - Parameters:
    ///   - authenticationCode: The authentication code.
    ///   - authenticatedData: The authenticated data.
    ///   - keyData: The symmetric key data used to secure the computation.
    static func validationPublisher(
        for authenticationCode: Data,
        authenticating authenticatedData: some DataProtocol,
        keyData: some SecureData
    ) -> AnyPublisher<Bool, Never> {
        Future { promise in
            let isValid = isValidAuthenticationCode(authenticationCode, authenticating: authenticatedData, keyData: keyData)
            promise(.success(isValid))
        }
        .eraseToAnyPublisher()
    }
}
#endif

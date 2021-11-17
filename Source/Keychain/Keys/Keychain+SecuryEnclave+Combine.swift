// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
#if canImport(Combine)
import Combine
import LocalAuthentication

@available(iOS 13, *)
public extension Keychain {
    /// Returns a publisher that performs a keychain query for a Secure Enclave key.
    ///
    /// - Attention: Make sure you use unique tag values for Secure Enclave and regular ECC keys.
    /// Saving a Secure Enclave ECC key and a regular ECC key with the same tag may cause undefined behavior when trying to query or delete a key via this tag.
    ///
    /// - Parameters:
    ///   - tag: The private tag data used for the search.
    ///   - accessGroup: Keychain Access group for whith the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - authentication: Keychain query authentication.
    ///
    /// - Returns: A publisher which queries and publishes an ECC Secure Enclave private key instance if the item could be found or `nil` if the query didn't return a result.
    static func queryKeyPublisher<PK>(
        withTag tag: String,
        accessGroup: String = Keychain.defaultAccessGroup,
        authentication: Keychain.QueryAuthentication = .default
    ) -> AnyPublisher<PK?, Error>
        where
        PK: ECCSecureEnclaveKey & DefinesSecKeyClass & CreateableFromSecKey
    {
        Future { promise in
            queryKey(withTag: tag, accessGroup: accessGroup, authentication: authentication) { result in
                promise(result)
            }
        }
        .eraseToAnyPublisher()
    }
}
#endif

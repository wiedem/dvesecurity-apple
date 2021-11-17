// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
#if canImport(Combine)
import Combine
import LocalAuthentication

@available(iOS 13, *)
public extension Keychain {
    /// Returns a publisher that performs a keychain query for a private RSA key and a given public key.
    ///
    /// - Parameters:
    ///   - publicKey: RSA public key for which the private key should be queried.
    ///   - tag: The private tag data used for the query.
    ///   - accessGroup: Keychain access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - authentication: Keychain query authentication. See ``Keychain/QueryAuthentication``  for more details.
    static func queryKeyPublisher<K, PK>(
        for publicKey: K,
        withTag tag: String? = nil,
        accessGroup: String = Keychain.defaultAccessGroup,
        authentication: Keychain.QueryAuthentication = .default
    ) -> AnyPublisher<PK?, Error>
        where
        K: RSAPublicKey & PKCS1Convertible,
        PK: RSAPrivateKey & CreateableFromSecKey
    {
        Future { promise in
            queryKey(for: publicKey, withTag: tag, accessGroup: accessGroup, authentication: authentication) {
                promise($0)
            }
        }
        .eraseToAnyPublisher()
    }

    /// Returns a publisher that performs a  keychain query for a private RSA key and a given public key digest.
    ///
    /// - Parameters:
    ///   - publicKeySHA1: The RSA public key SHA-1 used to search for the corresponding RSA private key item.
    ///   - tag: The private tag data used for the query.
    ///   - accessGroup: Keychain access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - authentication: Keychain query authentication. See ``Keychain/QueryAuthentication``  for more details.
    static func queryKeyPublisher<PK>(
        withPublicKeySHA1 publicKeySHA1: Data,
        tag: String? = nil,
        accessGroup: String = Keychain.defaultAccessGroup,
        authentication: Keychain.QueryAuthentication = .default
    ) throws -> AnyPublisher<PK?, Error> where PK: RSAPrivateKey & CreateableFromSecKey {
        Future { promise in
            queryKey(withPublicKeySHA1: publicKeySHA1, tag: tag, accessGroup: accessGroup, authentication: authentication) {
                promise($0)
            }
        }
        .eraseToAnyPublisher()
    }

    /// Returns a publisher that performs a keychain query for a private RSA key and a given private tag data.
    ///
    /// - Parameters:
    ///   - tag: The private tag data used for the query.
    ///   - accessGroup: Keychain access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - authentication: Keychain query authentication. See ``Keychain/QueryAuthentication``  for more details.
    static func queryKeyPublisher<PK>(
        withTag tag: String,
        accessGroup: String = Keychain.defaultAccessGroup,
        authentication: Keychain.QueryAuthentication = .default
    ) throws -> AnyPublisher<PK?, Error> where PK: RSAPrivateKey & CreateableFromSecKey {
        Future { promise in
            queryKey(withTag: tag, accessGroup: accessGroup, authentication: authentication) {
                promise($0)
            }
        }
        .eraseToAnyPublisher()
    }

    /// Returns a publisher that saves an RSA private key to the keychain.
    ///
    /// Attempts to store an RSA private key in the keychain. To query the key from the keychain later, you must specify the same `tag`  value and `accessGroup`  that was used
    /// when saving.
    /// The `accessControl` parameter restricts the conditions under which an app can query the item, see ``Keychain/AccessControl`` for more details.
    ///
    /// - Parameters:
    ///   - privateKey: RSA private key to save in the keychain.
    ///   - tag: The private tag data used for the key.
    ///   - accessGroup: Keychain Access group for which the save should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - accessControl: Access control value of the key. Sets  the conditions under which an app can access the item.
    ///   - authenticationContext: A local authentication context to use.
    static func saveKeyPublisher<PK>(
        for privateKey: PK,
        withTag tag: String,
        accessGroup: String = Keychain.defaultAccessGroup,
        accessControl: Keychain.AccessControl = .afterFirstUnlockThisDeviceOnly,
        authenticationContext: LAContext? = nil
    ) -> AnyPublisher<Keychain.Type, Error> where PK: RSAPrivateKey & ConvertibleToSecKey {
        Future { promise in
            do {
                try saveKey(
                    privateKey,
                    withTag: tag,
                    accessGroup: accessGroup,
                    accessControl: accessControl,
                    authenticationContext: authenticationContext
                )
                promise(.success(Self.self))
            } catch {
                promise(.failure(error))
            }
        }
        .eraseToAnyPublisher()
    }
}
#endif

// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
#if canImport(Combine)
import Combine
import LocalAuthentication

@available(iOS 13.0, *)
public extension Keychain {
    /// Returns a publisher that searches the keychain for a symmetric key.
    ///
    /// - Parameters:
    ///   - tag: The private tag data used for the search. See ``SecKeyAttributes/applicationTag``.
    ///   - applicationLabel: The application label used for the search of the corresponding symmetric key item. See ``SecKeyAttributes/applicationLabel``.
    ///   - accessGroup: Keychain access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - authentication: Keychain query authentication.
    static func queryKeyPublisher<K>(
        withTag tag: String,
        applicationLabel: Data? = nil,
        accessGroup: String = Keychain.defaultAccessGroup,
        authentication: Keychain.QueryAuthentication = .default
    ) -> AnyPublisher<K?, Error> where K: SymmetricKey & RawKeyConvertible {
        Future { promise in
            queryKey(withTag: tag, applicationLabel: applicationLabel, accessGroup: accessGroup, authentication: authentication) { result in
                promise(result)
            }
        }
        .eraseToAnyPublisher()
    }

    /// Returns a publisher that saves a symmetric key to the keychain.
    ///
    /// - Parameters:
    ///   - key: The symmetric key to save.
    ///   - tag: The private tag data used for the save. See ``SecKeyAttributes/applicationTag``.
    ///   - applicationLabel: The application label for the symmetric key item. See ``SecKeyAttributes/applicationLabel``.
    ///   - accessGroup: Keychain Access group for which the save should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - accessControl: Indicates when your application needs access to an item's data.  You should choose the most restrictive option that meets your application's needs to allow the system to protect that item in the best way possible.
    ///   - authenticationContext: A local authentication context to use.
    static func saveKeyPublisher<K>(
        for key: K,
        withTag tag: String,
        applicationLabel: Data?,
        accessGroup: String = Keychain.defaultAccessGroup,
        accessControl: Keychain.AccessControl = .afterFirstUnlockThisDeviceOnly,
        authenticationContext: LAContext? = nil
    ) -> AnyPublisher<Keychain.Type, Error> where K: SymmetricKey & RawKeyConvertible {
        Future { promise in
            do {
                try saveKey(
                    key,
                    withTag: tag,
                    applicationLabel: applicationLabel,
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

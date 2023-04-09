// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import LocalAuthentication

public extension Keychain {
    /// Performs a synchronous keychain query for a symmetric key.
    ///
    /// This function returns a symmetric key instance for the first match found.
    ///
    /// - Note: Use the ``queryKey(withTag:applicationLabel:accessGroup:authentication:completion:)-295i7`` if you don't want to block the calling thread.
    ///
    /// - Parameters:
    ///   - tag: The private tag data used for the search. See ``SecKeyAttributes/applicationTag``.
    ///   - applicationLabel: The application label used for the search of the corresponding symmetric key item. See ``SecKeyAttributes/applicationLabel``.
    ///   - accessGroup: Keychain Access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - authentication: The keychain query authentication to use for the operation. See ``Keychain/QueryAuthentication``  for more details.
    ///
    /// - Returns: Key data of the symmetric key if the item could be found, `nil` otherwise.
    static func queryKey(
        withTag tag: String,
        applicationLabel: Data?,
        accessGroup: String = defaultAccessGroup,
        authentication: QueryAuthentication = .default
    ) throws -> Crypto.KeyData? {
        var itemAttributes: Set<ItemAttribute> = [
            .applicationTag(tag), .accessGroup(accessGroup),
        ]
        applicationLabel.updateMapped({ .applicationLabel($0) }, in: &itemAttributes)

        return try CryptoKey.queryOneSymmetricKey(itemAttributes: itemAttributes, authentication: authentication)
    }

    /// Performs an asynchronous keychain query for a symmetric key.
    ///
    /// This function returns a symmetric key instance for the first match found.
    ///
    /// - Parameters:
    ///   - tag: The private tag data used for the search. See ``SecKeyAttributes/applicationTag``.
    ///   - applicationLabel: The application label used for the search of the corresponding symmetric key item. See ``SecKeyAttributes/applicationLabel``.
    ///   - accessGroup: Keychain Access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - authentication: The keychain query authentication to use for the operation. See ``Keychain/QueryAuthentication``  for more details.
    ///   - completion: The completion handler called after the query is completed. This handler is executed on a background thread.
    static func queryKey(
        withTag tag: String,
        applicationLabel: Data?,
        accessGroup: String = defaultAccessGroup,
        authentication: QueryAuthentication = .default,
        completion: @escaping (Result<Crypto.KeyData?, Error>) -> Void
    ) {
        var itemAttributes: Set<ItemAttribute> = [
            .applicationTag(tag), .accessGroup(accessGroup),
        ]
        applicationLabel.updateMapped({ .applicationLabel($0) }, in: &itemAttributes)

        CryptoKey.queryOneSymmetricKey(itemAttributes: itemAttributes, authentication: authentication, completion: completion)
    }

    /// Add a symmetric key to the keychain.
    ///
    /// Saves a non-synchronizable symmetric key in the keychain. The item is uniquely identified by a tag and an optional application label.
    ///
    /// An entry with the same tag and application label must not yet exist in the keychain, otherwise the error ``KeychainError/itemSavingFailed(status:)``  will be thrown with a status code value `errSecDuplicateItem`.
    ///
    /// - Parameters:
    ///   - key: The symmetric key to save.
    ///   - tag: The private tag data used for the save. See ``SecKeyAttributes/applicationTag``.
    ///   - applicationLabel: The application label for the symmetric key item. See ``SecKeyAttributes/applicationLabel``.
    ///   - accessGroup: Keychain Access group for which the save should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - accessControl: Indicates when your application needs access to an item's data.  You should choose the most restrictive option that meets your application's needs to allow the system to protect that item in the best way possible.
    ///   - label: A keychain item label that can be displayed to the user by apps that have access to the item.
    ///   - authenticationContext: A local authentication context to use.
    static func saveKey(
        _ key: some SecureData,
        withTag tag: String,
        applicationLabel: Data?,
        accessGroup: String = defaultAccessGroup,
        accessControl: AccessControl = .afterFirstUnlockThisDeviceOnly,
        label: String? = nil,
        authenticationContext: LAContext? = nil
    ) throws {
        var itemAttributes: Set<ItemAttribute> = [
            .applicationTag(tag),
            .keySizeInBits(key.bitCount),
            .accessControl(accessControl),
            .accessGroup(accessGroup),
        ]
        applicationLabel.updateMapped({ .applicationLabel($0) }, in: &itemAttributes)
        label.updateMapped({ .label($0) }, in: &itemAttributes)

        try CryptoKey.save(
            keyClass: .symmetric,
            keyData: key,
            itemAttributes: itemAttributes
        )
    }

    /// Updates a symmetric key in the keychain.
    ///
    /// Updates a non-synchronizable symmetic key in the keychain identified by the specified tag and application label.
    ///
    /// - Parameters:
    ///   - newKey: The new symmetric key with which the found key should be replaced.
    ///   - tag: The private tag data used for the save. See ``SecKeyAttributes/applicationTag``.
    ///   - applicationLabel: The application label for the symmetric key item. See ``SecKeyAttributes/applicationLabel``.
    ///   - accessGroup: Keychain Access group for which the update should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - authentication: The keychain query authentication to use for the operation. See ``Keychain/QueryAuthentication``  for more details.
    static func updateKey(
        newKey: some SecureData,
        withTag tag: String,
        applicationLabel: Data?,
        accessGroup: String = defaultAccessGroup,
        authentication: QueryAuthentication = .default
    ) throws {
        var itemAttributes: Set<ItemAttribute> = [
            .applicationTag(tag), .accessGroup(accessGroup),
        ]
        applicationLabel.updateMapped({ .applicationLabel($0) }, in: &itemAttributes)

        try CryptoKey.update(
            keyClass: .symmetric,
            newKeyData: newKey,
            itemAttributes: itemAttributes,
            authentication: authentication
        )
    }

    /// Deletes a symmetric key in the keychain.
    ///
    /// Deletes a non-sychronizable symmetric key identified by the specified tag and application label in the keychain.
    ///
    /// - Note: No error is thrown if no element with the specified parameters can be found. Instead, the method returns `false` as a return value.
    ///
    /// - Parameters:
    ///   - tag: The private tag data used for the deletion. See ``SecKeyAttributes/applicationTag``.
    ///   - applicationLabel: The application label used to delete the key item. See ``SecKeyAttributes/applicationLabel``.
    ///   - accessGroup: Keychain Access group for which the update should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///
    /// - Returns: `true` if an item matching the parameters was deleted, `false` otherwise.
    @discardableResult
    static func deleteKey(
        withTag tag: String,
        applicationLabel: Data?,
        accessGroup: String = defaultAccessGroup
    ) throws -> Bool {
        var itemAttributes: Set<ItemAttribute> = [.applicationTag(tag), .accessGroup(accessGroup)]
        applicationLabel.updateMapped({ .applicationLabel($0) }, in: &itemAttributes)

        return try CryptoKey.delete(keyClass: .symmetric, itemAttributes: itemAttributes)
    }
}

public extension Keychain {
    /// Performs an asynchronous keychain query for a symmetric key.
    ///
    /// This function returns a symmetric key instance for the first match found.
    ///
    /// - Parameters:
    ///   - tag: The private tag data used for the search. See ``SecKeyAttributes/applicationTag``.
    ///   - applicationLabel: The application label used for the search of the corresponding symmetric key item. See ``SecKeyAttributes/applicationLabel``.
    ///   - accessGroup: Keychain Access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - authentication: The keychain query authentication to use for the operation. See ``Keychain/QueryAuthentication``  for more details.
    ///
    /// - Returns: Key data of the symmetric key if the item could be found, `nil` otherwise.
    static func queryKey(
        withTag tag: String,
        applicationLabel: Data?,
        accessGroup: String = defaultAccessGroup,
        authentication: QueryAuthentication = .default
    ) async throws -> Crypto.KeyData? {
        try await withCheckedThrowingContinuation { continuation in
            queryKey(withTag: tag, applicationLabel: applicationLabel, accessGroup: accessGroup, authentication: authentication) {
                continuation.resume(with: $0)
            }
        }
    }
}

public extension Keychain {
    /// Performs a synchronous keychain query for a symmetric key.
    ///
    /// This function returns a symmetric key instance for the first match found.
    ///
    /// - Parameters:
    ///   - tag: The private tag data used for the search. See ``SecKeyAttributes/applicationTag``.
    ///   - applicationLabel: The application label used for the search of the corresponding symmetric key item. See ``SecKeyAttributes/applicationLabel``.
    ///   - accessGroup: Keychain Access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - authentication: The keychain query authentication to use for the operation. See ``Keychain/QueryAuthentication``  for more details.
    ///
    /// - Returns: Key data of the symmetric key if the item could be found, `nil` otherwise.
    static func queryKey<K>(
        withTag tag: String,
        applicationLabel: Data?,
        accessGroup: String = defaultAccessGroup,
        authentication: QueryAuthentication = .default
    ) throws -> K? where K: KeyDataRepresentable {
        guard let keyData = try queryKey(
            withTag: tag, applicationLabel: applicationLabel,
            accessGroup: accessGroup,
            authentication: authentication
        ) else {
            return nil
        }

        return try K(keyData: keyData)
    }

    /// Performs an asynchronous keychain query for a symmetric key.
    ///
    /// This function returns a symmetric key instance for the first match found.
    ///
    /// - Parameters:
    ///   - tag: The private tag data used for the search. See ``SecKeyAttributes/applicationTag``.
    ///   - applicationLabel: The application label used for the search of the corresponding symmetric key item. See ``SecKeyAttributes/applicationLabel``.
    ///   - accessGroup: Keychain Access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - authentication: The keychain query authentication to use for the operation. See ``Keychain/QueryAuthentication``  for more details.
    ///   - completion: The completion handler called after the query is completed. This handler is executed on a background thread.
    static func queryKey<K>(
        withTag tag: String,
        applicationLabel: Data?,
        accessGroup: String = defaultAccessGroup,
        authentication: QueryAuthentication = .default,
        completion: @escaping (Result<K?, Error>) -> Void
    ) where K: KeyDataRepresentable {
        queryKey(withTag: tag, applicationLabel: applicationLabel, accessGroup: accessGroup, authentication: authentication) { result in
            switch result {
            case let .success(keyData):
                guard let keyData else {
                    completion(.success(nil))
                    return
                }
                do {
                    let key = try K(keyData: keyData)
                    completion(.success(key))
                } catch {
                    completion(.failure(error))
                }

            case let .failure(error):
                completion(.failure(error))
            }
        }
    }

    /// Add a symmetric key to the keychain.
    ///
    /// Saves a non-synchronizable symmetric key in the keychain. The item is uniquely identified by a tag and an optional application label.
    ///
    /// An entry with the same tag and application label must not yet exist in the keychain, otherwise the error ``KeychainError/itemSavingFailed(status:)``  will be thrown with a status code value `errSecDuplicateItem`.
    ///
    /// - Parameters:
    ///   - key: The symmetric key to save.
    ///   - tag: The private tag data used for the save. See ``SecKeyAttributes/applicationTag``.
    ///   - applicationLabel: The application label for the symmetric key item. See ``SecKeyAttributes/applicationLabel``.
    ///   - accessGroup: Keychain Access group for which the save should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - accessControl: Indicates when your application needs access to an item's data.  You should choose the most restrictive option that meets your application's needs to allow the system to protect that item in the best way possible.
    ///   - label: A keychain item label that can be displayed to the user by apps that have access to the item.
    ///   - authenticationContext: A local authentication context to use.
    static func saveKey(
        _ key: some KeyDataRepresentable,
        withTag tag: String,
        applicationLabel: Data?,
        accessGroup: String = defaultAccessGroup,
        accessControl: AccessControl = .afterFirstUnlockThisDeviceOnly,
        label: String? = nil,
        authenticationContext: LAContext? = nil
    ) throws {
        try saveKey(
            key.keyData,
            withTag: tag,
            applicationLabel: applicationLabel,
            accessGroup: accessGroup,
            accessControl: accessControl,
            label: label,
            authenticationContext: authenticationContext
        )
    }

    /// Updates a symmetric key in the keychain.
    ///
    /// Updates a non-synchronizable symmetic key in the keychain identified by the specified tag and application label.
    ///
    /// - Parameters:
    ///   - newKey: The new symmetric key with which the found key should be replaced.
    ///   - tag: The private tag data used for the save. See ``SecKeyAttributes/applicationTag``.
    ///   - applicationLabel: The application label for the symmetric key item. See ``SecKeyAttributes/applicationLabel``.
    ///   - accessGroup: Keychain Access group for which the update should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - authentication: The keychain query authentication to use for the operation. See ``Keychain/QueryAuthentication``  for more details.
    static func updateKey(
        newKey: some KeyDataRepresentable,
        withTag tag: String,
        applicationLabel: Data?,
        accessGroup: String = defaultAccessGroup,
        authentication: QueryAuthentication = .default
    ) throws {
        try updateKey(
            newKey: newKey.keyData,
            withTag: tag,
            applicationLabel: applicationLabel,
            accessGroup: accessGroup,
            authentication: authentication
        )
    }
}

public extension Keychain {
    /// Performs an asynchronous keychain query for a symmetric key.
    ///
    /// This function returns a symmetric key instance for the first match found.
    ///
    /// - Parameters:
    ///   - tag: The private tag data used for the search. See ``SecKeyAttributes/applicationTag``.
    ///   - applicationLabel: The application label used for the search of the corresponding symmetric key item. See ``SecKeyAttributes/applicationLabel``.
    ///   - accessGroup: Keychain Access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - authentication: The keychain query authentication to use for the operation. See ``Keychain/QueryAuthentication``  for more details.
    ///
    /// - Returns: Key data of the symmetric key if the item could be found, `nil` otherwise.
    static func queryKey<K>(
        withTag tag: String,
        applicationLabel: Data?,
        accessGroup: String = defaultAccessGroup,
        authentication: QueryAuthentication = .default
    ) async throws -> K? where K: KeyDataRepresentable {
        try await withCheckedThrowingContinuation { continuation in
            queryKey(withTag: tag, applicationLabel: applicationLabel, accessGroup: accessGroup, authentication: authentication) {
                continuation.resume(with: $0)
            }
        }
    }
}

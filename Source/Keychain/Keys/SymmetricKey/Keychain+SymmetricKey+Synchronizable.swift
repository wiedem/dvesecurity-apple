// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

public extension Keychain {
    /// Performs a synchronous keychain query for a synchronized symmetric key.
    ///
    /// This function returns a symmetric key instance for the first match found.
    ///
    /// - Note: Use the ``querySynchronizableKey(withTag:applicationLabel:accessGroup:completion:)-6nui1`` if you don't want to block the calling thread.
    ///
    /// - Parameters:
    ///   - tag: The private tag data used for the search. See ``SecKeyAttributes/applicationTag``.
    ///   - applicationLabel: The application label used for the search of the corresponding symmetric key item. See ``SecKeyAttributes/applicationLabel``.
    ///   - accessGroup: Keychain Access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///
    /// - Returns: Key data of the symmetric key if the item could be found, `nil` otherwise.
    static func querySynchronizableKey(
        withTag tag: String,
        applicationLabel: Data?,
        accessGroup: String = defaultAccessGroup
    ) throws -> Crypto.KeyData? {
        var itemAttributes: Set<ItemAttribute> = [
            .applicationTag(tag), .accessGroup(accessGroup), .synchronizable(),
        ]
        applicationLabel.updateMapped({ .applicationLabel($0) }, in: &itemAttributes)

        return try CryptoKey.queryOneSymmetricKey(itemAttributes: itemAttributes)
    }

    /// Performs an asynchronous keychain query for a synchronized symmetric key.
    ///
    /// This function returns a symmetric key instance for the first match found.
    ///
    /// - Parameters:
    ///   - tag: The private tag data used for the search. See ``SecKeyAttributes/applicationTag``.
    ///   - applicationLabel: The application label used for the search of the corresponding symmetric key item. See ``SecKeyAttributes/applicationLabel``.
    ///   - accessGroup: Keychain Access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - completion: The completion handler called after the query is completed. This handler is executed on a background thread.
    static func querySynchronizableKey(
        withTag tag: String,
        applicationLabel: Data?,
        accessGroup: String = defaultAccessGroup,
        completion: @escaping (Result<Crypto.KeyData?, Error>) -> Void
    ) {
        var itemAttributes: Set<ItemAttribute> = [
            .applicationTag(tag), .accessGroup(accessGroup), .synchronizable(),
        ]
        applicationLabel.updateMapped({ .applicationLabel($0) }, in: &itemAttributes)

        CryptoKey.queryOneSymmetricKey(itemAttributes: itemAttributes, completion: completion)
    }

    /// Saves a synchronized symmetric key to the keychain.
    ///
    /// - Parameters:
    ///   - key: The symmetric key to save.
    ///   - tag: The private tag data used for the save. See ``SecKeyAttributes/applicationTag``.
    ///   - applicationLabel: The application label for the symmetric key item. See ``SecKeyAttributes/applicationLabel``.
    ///   - accessGroup: Keychain Access group for which the save should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - accessibility: Indicates when your application needs access to an item's data.  You should choose the most restrictive option that meets your application's needs to allow the system to protect that item in the best way possible.
    ///   - label: A keychain item label that can be displayed to the user by apps that have access to the item.
    static func saveSynchronizableKey(
        _ key: some SecureData,
        withTag tag: String,
        applicationLabel: Data?,
        accessGroup: String = defaultAccessGroup,
        accessibility: SynchronizableItemAccessibility = .afterFirstUnlock,
        label: String? = nil
    ) throws {
        var itemAttributes: Set<ItemAttribute> = [
            .accessGroup(accessGroup),
            .synchronizable(accessibility: accessibility),
            .applicationTag(tag),
            .keySizeInBits(key.bitCount),
        ]
        applicationLabel.updateMapped({ .applicationLabel($0) }, in: &itemAttributes)
        label.updateMapped({ .label($0) }, in: &itemAttributes)

        try CryptoKey.save(
            keyClass: .symmetric,
            keyData: key,
            itemAttributes: itemAttributes
        )
    }

    /// Updates a synchronized symmetric key in the keychain.
    ///
    /// - Parameters:
    ///   - newKey: The new symmetric key with which the found key should be replaced.
    ///   - tag: The private tag data used for the save. See ``SecKeyAttributes/applicationTag``.
    ///   - applicationLabel: The application label for the symmetric key item. See ``SecKeyAttributes/applicationLabel``.
    ///   - accessGroup: Keychain Access group for which the update should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    static func updateSynchronizableKey(
        newKey: some SecureData,
        withTag tag: String,
        applicationLabel: Data?,
        accessGroup: String = defaultAccessGroup
    ) throws {
        var itemAttributes: Set<ItemAttribute> = [
            .applicationTag(tag),
            .accessGroup(accessGroup),
            .synchronizable(),
        ]
        applicationLabel.updateMapped({ .applicationLabel($0) }, in: &itemAttributes)

        try CryptoKey.update(
            keyClass: .symmetric,
            newKeyData: newKey,
            itemAttributes: itemAttributes
        )
    }

    /// Deletes a synchronized symmetric key in the keychain.
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
    static func deleteSynchronizableKey(
        withTag tag: String,
        applicationLabel: Data?,
        accessGroup: String = defaultAccessGroup
    ) throws -> Bool {
        var itemAttributes: Set<ItemAttribute> = [
            .applicationTag(tag), .accessGroup(accessGroup), .synchronizable(),
        ]
        applicationLabel.updateMapped({ .applicationLabel($0) }, in: &itemAttributes)

        return try CryptoKey.delete(keyClass: .symmetric, itemAttributes: itemAttributes)
    }
}

public extension Keychain {
    /// Performs an asynchronous keychain query for a synchronized symmetric key.
    ///
    /// This function returns a symmetric key instance for the first match found.
    ///
    /// - Parameters:
    ///   - tag: The private tag data used for the search. See ``SecKeyAttributes/applicationTag``.
    ///   - applicationLabel: The application label used for the search of the corresponding symmetric key item. See ``SecKeyAttributes/applicationLabel``.
    ///   - accessGroup: Keychain Access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///
    /// - Returns: Key data of the symmetric key if the item could be found, `nil` otherwise.
    static func querySynchronizableKey(
        withTag tag: String,
        applicationLabel: Data?,
        accessGroup: String = defaultAccessGroup
    ) async throws -> Crypto.KeyData? {
        try await withCheckedThrowingContinuation { continuation in
            querySynchronizableKey(withTag: tag, applicationLabel: applicationLabel, accessGroup: accessGroup) {
                continuation.resume(with: $0)
            }
        }
    }
}

public extension Keychain {
    /// Performs a synchronous keychain query for a synchronized symmetric key.
    ///
    /// This function returns a symmetric key instance for the first match found.
    ///
    /// - Parameters:
    ///   - tag: The private tag data used for the search. See ``SecKeyAttributes/applicationTag``.
    ///   - applicationLabel: The application label used for the search of the corresponding symmetric key item. See ``SecKeyAttributes/applicationLabel``.
    ///   - accessGroup: Keychain Access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///
    /// - Returns: Key data of the symmetric key if the item could be found, `nil` otherwise.
    static func querySynchronizableKey<K>(
        withTag tag: String,
        applicationLabel: Data?,
        accessGroup: String = defaultAccessGroup
    ) throws -> K? where K: KeyDataRepresentable {
        guard let keyData = try querySynchronizableKey(withTag: tag, applicationLabel: applicationLabel, accessGroup: accessGroup) else {
            return nil
        }

        return try K(keyData: keyData)
    }

    /// Performs an asynchronous keychain query for a synchronized symmetric key.
    ///
    /// This function returns a symmetric key instance for the first match found.
    ///
    /// - Parameters:
    ///   - tag: The private tag data used for the search. See ``SecKeyAttributes/applicationTag``.
    ///   - applicationLabel: The application label used for the search of the corresponding symmetric key item. See ``SecKeyAttributes/applicationLabel``.
    ///   - accessGroup: Keychain Access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - completion: The completion handler called after the query is completed. This handler is executed on a background thread.
    static func querySynchronizableKey<K>(
        withTag tag: String,
        applicationLabel: Data?,
        accessGroup: String = defaultAccessGroup,
        completion: @escaping (Result<K?, Error>) -> Void
    ) where K: KeyDataRepresentable {
        querySynchronizableKey(withTag: tag, applicationLabel: applicationLabel, accessGroup: accessGroup) { result in
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

    /// Saves a synchronized symmetric key to the keychain.
    ///
    /// - Parameters:
    ///   - key: The symmetric key to save.
    ///   - tag: The private tag data used for the save. See ``SecKeyAttributes/applicationTag``.
    ///   - applicationLabel: The application label for the symmetric key item. See ``SecKeyAttributes/applicationLabel``.
    ///   - accessGroup: Keychain Access group for which the save should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - accessibility: Indicates when your application needs access to an item's data.  You should choose the most restrictive option that meets your application's needs to allow the system to protect that item in the best way possible.
    ///   - label: A keychain item label that can be displayed to the user by apps that have access to the item.
    static func saveSynchronizableKey(
        _ key: some KeyDataRepresentable,
        withTag tag: String,
        applicationLabel: Data?,
        accessGroup: String = defaultAccessGroup,
        accessibility: SynchronizableItemAccessibility = .afterFirstUnlock,
        label: String? = nil
    ) throws {
        try saveSynchronizableKey(
            key.keyData,
            withTag: tag,
            applicationLabel: applicationLabel,
            accessGroup: accessGroup,
            accessibility: accessibility,
            label: label
        )
    }

    /// Updates a synchronized symmetric key in the keychain.
    ///
    /// - Parameters:
    ///   - newKey: The new symmetric key with which the found key should be replaced.
    ///   - tag: The private tag data used for the save. See ``SecKeyAttributes/applicationTag``.
    ///   - applicationLabel: The application label for the symmetric key item. See ``SecKeyAttributes/applicationLabel``.
    ///   - accessGroup: Keychain Access group for which the update should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    static func updateSynchronizableKey(
        newKey: some KeyDataRepresentable,
        withTag tag: String,
        applicationLabel: Data?,
        accessGroup: String = defaultAccessGroup
    ) throws {
        try updateSynchronizableKey(
            newKey: newKey.keyData,
            withTag: tag,
            applicationLabel: applicationLabel,
            accessGroup: accessGroup
        )
    }
}

public extension Keychain {
    /// Performs an asynchronous keychain query for a synchronized symmetric key.
    ///
    /// This function returns a symmetric key instance for the first match found.
    ///
    /// - Parameters:
    ///   - tag: The private tag data used for the search. See ``SecKeyAttributes/applicationTag``.
    ///   - applicationLabel: The application label used for the search of the corresponding symmetric key item. See ``SecKeyAttributes/applicationLabel``.
    ///   - accessGroup: Keychain Access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///
    /// - Returns: Key data of the symmetric key if the item could be found, `nil` otherwise.
    static func querySynchronizableKey<K>(
        withTag tag: String,
        applicationLabel: Data?,
        accessGroup: String = defaultAccessGroup
    ) async throws -> K? where K: KeyDataRepresentable {
        try await withCheckedThrowingContinuation { continuation in
            querySynchronizableKey(withTag: tag, applicationLabel: applicationLabel, accessGroup: accessGroup) {
                continuation.resume(with: $0)
            }
        }
    }
}

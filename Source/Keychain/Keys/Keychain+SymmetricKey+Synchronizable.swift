// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

public extension Keychain {
    /// Performs a keychain query for a synchronized symmetric key.
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
    ) where K: SymmetricKey & RawKeyConvertible {
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
    static func saveSynchronizableKey<K>(
        _ key: K,
        withTag tag: String,
        applicationLabel: Data?,
        accessGroup: String = defaultAccessGroup,
        accessibility: SynchronizableItemAccessibility = .afterFirstUnlock,
        label: String? = nil
    ) throws where K: SymmetricKey & RawKeyConvertible {
        var itemAttributes: Set<ItemAttribute> = [
            .accessGroup(accessGroup),
            .synchronizable(accessibility: accessibility),
            .applicationTag(tag),
            .keySizeInBits(key.bitCount),
        ]
        applicationLabel.updateMapped({ .applicationLabel($0) }, in: &itemAttributes)
        label.updateMapped({ .label($0) }, in: &itemAttributes)

        try CryptoKey.save(keyClass: .symmetric,
                           keyData: key.rawKeyRepresentation,
                           itemAttributes: itemAttributes)
    }

    /// Updates a synchronized symmetric key in the keychain.
    ///
    /// - Parameters:
    ///   - newKey: The new symmetric key with which the found key should be replaced.
    ///   - tag: The private tag data used for the save. See ``SecKeyAttributes/applicationTag``.
    ///   - applicationLabel: The application label for the symmetric key item. See ``SecKeyAttributes/applicationLabel``.
    ///   - accessGroup: Keychain Access group for which the update should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    static func updateSynchronizableKey<K>(
        newKey: K,
        withTag tag: String,
        applicationLabel: Data?,
        accessGroup: String = defaultAccessGroup
    ) throws where K: SymmetricKey & RawKeyConvertible {
        var itemAttributes: Set<ItemAttribute> = [
            .applicationTag(tag),
            .accessGroup(accessGroup),
            .synchronizable(),
        ]
        applicationLabel.updateMapped({ .applicationLabel($0) }, in: &itemAttributes)

        try CryptoKey.update(
            keyClass: .symmetric,
            newKeyData: newKey.rawKeyRepresentation,
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

// MARK: - iOS 13
@available(iOS 13.0, *)
public extension Keychain {
    /// Performs a keychain query for a synchronized symmetric key.
    ///
    /// This function returns a symmetric key instance for the first match found.
    ///
    /// - Parameters:
    ///   - tag: The private tag data used for the search. See ``SecKeyAttributes/applicationTag``.
    ///   - applicationLabel: The application label used for the search of the corresponding symmetric key item. See ``SecKeyAttributes/applicationLabel``.
    ///   - accessGroup: Keychain Access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///
    /// - Returns: Symmetric key instance of type `K` if the item could be found, `nil` otherwise.
    static func querySynchronizableKey<K>(
        withTag tag: String,
        applicationLabel: Data?,
        accessGroup: String = defaultAccessGroup
    ) throws -> K? where K: SymmetricKey & RawKeyConvertible {
        var itemAttributes: Set<ItemAttribute> = [
            .applicationTag(tag), .accessGroup(accessGroup), .synchronizable(),
        ]
        applicationLabel.updateMapped({ .applicationLabel($0) }, in: &itemAttributes)

        guard let keyData: Data = try CryptoKey.queryOneSymmetricKey(itemAttributes: itemAttributes) else {
            return nil
        }
        return try K(rawKeyRepresentation: keyData)
    }
}

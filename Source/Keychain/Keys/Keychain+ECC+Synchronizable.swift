// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

public extension Keychain {
    /// Performs a keychain query for a synchronized private ECC key and a given public key.
    ///
    /// This function returns an ECC private key instance for the first match found. The type of the returned item has to conform to the ``ECCPrivateKey`` protocol.
    ///
    /// - Parameters:
    ///   - publicKey: The ECC public key used to search for the corresponding ECC private key item.
    ///   - tag: The private tag data used for the search.
    ///   - accessGroup: Keychain Access group for whith the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - completion: The completion handler called after the query is completed. This handler is executed on a background thread.
    ///
    /// - Returns: ECC private key instance if the item could be found, `nil` otherwise.
    static func querySynchronizableKey<K, PK>(
        for publicKey: K,
        withTag tag: String? = nil,
        accessGroup: String = defaultAccessGroup,
        completion: @escaping (Result<PK?, Error>) -> Void
    ) where
        K: ECCPublicKey,
        PK: ECCPrivateKey & CreateableFromSecKey
    {
        let publicKeySHA1 = Hashing.Insecure.SHA1.hash(publicKey.x963Representation)
        querySynchronizableKey(withPublicKeySHA1: publicKeySHA1, tag: tag, accessGroup: accessGroup, completion: completion)
    }

    /// Performs a keychain query for a synchronized private ECC key and a given public key digest.
    ///
    /// This function returns an ECC private key instance for the first match found. The type of the returned item has to conform to the ``ECCPrivateKey`` protocol.
    ///
    /// - Parameters:
    ///   - publicKeySHA1: The ECC public key SHA-1 used to search for the corresponding ECC private key item.
    ///   - tag: The private tag data used for the search.
    ///   - accessGroup: Keychain Access group for whith the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///
    /// - Returns: ECC private key instance if the item could be found, `nil` otherwise.
    static func querySynchronizableKey<PK>(
        withPublicKeySHA1 publicKeySHA1: Data,
        tag: String? = nil,
        accessGroup: String = defaultAccessGroup,
        completion: @escaping (Result<PK?, Error>) -> Void
    ) where PK: ECCPrivateKey & CreateableFromSecKey {
        var itemAttributes: Set<ItemAttribute> = [
            .applicationLabel(publicKeySHA1), .accessGroup(accessGroup), .synchronizable(),
        ]
        tag.updateMapped({ .applicationTag($0) }, in: &itemAttributes)

        CryptoKey.queryOne(keyClass: PK.secKeyClass, itemAttributes: itemAttributes, completion: completion)
    }

    /// Performs a keychain query for a synchronized private ECC key and a given private tag data.
    ///
    /// This function returns an ECC private key instance for the first match found. The type of the returned item has to conform to the ``ECCPrivateKey`` protocol.
    ///
    /// - Attention: Make sure you use unique tag values for Secure Enclave and regular ECC keys.
    /// Saving a Secure Enclave ECC key and a regular ECC key with the same tag may cause undefined behavior when trying to query or delete a key via this tag.
    ///
    /// - Parameters:
    ///   - tag: The private tag data used for the search.
    ///   - accessGroup: Keychain Access group for whith the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///
    /// - Returns: ECC private key instance if the item could be found, `nil` otherwise.
    static func querySynchronizableKey<PK>(
        withTag tag: String,
        accessGroup: String = defaultAccessGroup,
        completion: @escaping (Result<PK?, Error>) -> Void
    ) where PK: ECCPrivateKey & CreateableFromSecKey {
        let itemAttributes: Set<ItemAttribute> = [
            .applicationTag(tag), .accessGroup(accessGroup), .synchronizable(),
        ]
        CryptoKey.queryOne(keyClass: PK.secKeyClass, itemAttributes: itemAttributes, completion: completion)
    }

    /// Saves an synchronized ECC private key to the keychain.
    ///
    /// Attempts to store an ECC private key in the keychain. To query the key from the keychain later, you must specify the same `tag`  value and `accessGroup`  that was used when saving.
    ///
    /// - Parameters:
    ///   - privateKey: ECC private key to save in the keychain.
    ///   - tag: The private tag data used for the key.
    ///   - accessGroup: Keychain Access group for which the save should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - accessibility: Accessibility of the key. Sets the conditions under which an app can access the item.
    ///   - label: A keychain item label that can be displayed to the user by apps that have access to the item.
    ///
    /// - Throws: ``KeychainError/itemSavingFailed(status:)`` with a `errSecDuplicateItem` status code if the item already exists in the keychain.
    static func saveSynchronizableKey<PK>(
        _ privateKey: PK,
        withTag tag: String,
        accessGroup: String = defaultAccessGroup,
        accessibility: SynchronizableItemAccessibility = .afterFirstUnlock,
        label: String? = nil
    ) throws where PK: ECCPrivateKey & ConvertibleToSecKey {
        var itemAttributes: Set<ItemAttribute> = [
            .applicationTag(tag), .accessGroup(accessGroup), .synchronizable(accessibility: accessibility),
        ]
        label.updateMapped({ .label($0) }, in: &itemAttributes)

        try CryptoKey.save(keyClass: PK.secKeyClass, secKey: privateKey.secKey, itemAttributes: itemAttributes)
    }

    /// Deletes an synchronized ECC private key in the keychain.
    ///
    /// - Note: No error is thrown if no element with the specified parameters can be found. Instead, the method returns `false` as a return value.
    ///
    /// - Parameters:
    ///   - publicKey: The ECC public key of the private key to delete in the keychain.
    ///   - tag: The private tag data used for the key.
    ///   - accessGroup: Keychain Access group for which the delete should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///
    /// - Returns: `true` if an item matching the parameters was deleted, `false` otherwise.
    @discardableResult
    static func deleteSynchronizablePrivateKey<K>(
        for publicKey: K,
        withTag tag: String,
        accessGroup: String = defaultAccessGroup
    ) throws -> Bool where K: ECCPublicKey {
        let publicKeySHA1 = Hashing.Insecure.SHA1.hash(publicKey.x963Representation)
        return try deleteSynchronizableKey(ofType: Crypto.ECC.PrivateKey.self, withTag: tag, publicKeySHA1: publicKeySHA1, accessGroup: accessGroup)
    }

    /// Deletes an synchronized ECC private key in the keychain.
    ///
    /// - Note: No error is thrown if no element with the specified parameters can be found. Instead, the method returns `false` as a return value.
    ///
    /// - Parameters:
    ///   - privateKey: ECC private key to delete in the keychain.
    ///   - tag: The private tag data used for the key.
    ///   - accessGroup: Keychain Access group for which the delete should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///
    /// - Returns: `true` if an item matching the parameters was deleted, `false` otherwise.
    @discardableResult
    static func deleteSynchronizableKey<PK>(
        _ privateKey: PK,
        withTag tag: String,
        accessGroup: String = defaultAccessGroup
    ) throws -> Bool where PK: ECCPrivateKey & ConvertibleToSecKey {
        let publicKey: Crypto.ECC.PublicKey = privateKey.publicKey()
        let publicKeySHA1 = Hashing.Insecure.SHA1.hash(publicKey.x963Representation)
        return try deleteSynchronizableKey(ofType: PK.self, withTag: tag, publicKeySHA1: publicKeySHA1, accessGroup: accessGroup)
    }

    /// Deletes any type of synchronized ECC key in the keychain.
    ///
    /// It is recommended to specify the public key hash to disambiguate the query for the key or to make sure that the key tag is unique in the access group.
    /// The deletion behavior is undefined If no public key hash is specified and a second key with the same type and tag exists in the keychain.
    ///
    /// - Note: No error is thrown if no element with the specified parameters can be found. Instead, the method returns `false` as a return value.
    ///
    /// - Parameters:
    ///   - type: Any type of `ECCKey` to delete.
    ///   - tag: The private tag data used for the key.
    ///   - publicKeySHA1: The SHA1 hash of the public key.
    ///   - accessGroup: Keychain Access group for which the delete should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///
    /// - Returns: `true` if an item matching the parameters was deleted, `false` otherwise.
    @discardableResult
    static func deleteSynchronizableKey<K>(
        ofType _: K.Type,
        withTag tag: String,
        publicKeySHA1: Data? = nil,
        accessGroup: String = defaultAccessGroup
    ) throws -> Bool where K: ECCKey & DefinesSecKeyClass {
        var itemAttributes: Set<ItemAttribute> = [
            .applicationTag(tag), .accessGroup(accessGroup), .synchronizable(),
        ]
        publicKeySHA1.updateMapped({ .applicationLabel($0) }, in: &itemAttributes)

        return try CryptoKey.delete(keyClass: K.secKeyClass, itemAttributes: itemAttributes)
    }
}

@available(iOS 13.0, *)
public extension Keychain {
    /// Performs a keychain query for a synchronized private ECC key and a given public key.
    ///
    /// This function returns an ECC private key instance for the first match found. The type of the returned item has to conform to the ``ECCPrivateKey`` protocol.
    ///
    /// - Parameters:
    ///   - publicKey: The ECC public key used to search for the corresponding ECC private key item.
    ///   - tag: The private tag data used for the search.
    ///   - accessGroup: Keychain Access group for whith the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///
    /// - Throws: ``KeychainError/ambiguousQueryResult`` if the query returns more than one item. Use a `tag` value if needed to make the query unique.
    /// - Returns: ECC private key instance if the item could be found, `nil` otherwise.
    static func querySynchronizableKey<K, PK>(
        for publicKey: K,
        withTag tag: String? = nil,
        accessGroup: String = Keychain.defaultAccessGroup
    ) throws -> PK?
        where
        K: ECCPublicKey,
        PK: ECCPrivateKey & CreateableFromSecKey
    {
        let publicKeySHA1 = Hashing.Insecure.SHA1.hash(publicKey.x963Representation)
        return try querySynchronizableKey(withPublicKeySHA1: publicKeySHA1, tag: tag, accessGroup: accessGroup)
    }

    /// Performs a keychain query for a synchronized private ECC key and a given public key digest.
    ///
    /// This function returns an ECC private key instance for the first match found. The type of the returned item has to conform to the ``ECCPrivateKey`` protocol.
    ///
    /// - Parameters:
    ///   - publicKeySHA1: The ECC public key SHA-1 used to search for the corresponding ECC private key item.
    ///   - tag: The private tag data used for the search.
    ///   - accessGroup: Keychain Access group for whith the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///
    /// - Throws: ``KeychainError/ambiguousQueryResult`` if the query returns more than one item. Use a `tag` value if needed to make the query unique.
    /// - Returns: ECC private key instance if the item could be found, `nil` otherwise.
    static func querySynchronizableKey<PK>(
        withPublicKeySHA1 publicKeySHA1: Data,
        tag: String? = nil,
        accessGroup: String = defaultAccessGroup
    ) throws -> PK? where PK: ECCPrivateKey & CreateableFromSecKey {
        var itemAttributes: Set<ItemAttribute> = [
            .accessGroup(accessGroup), .applicationLabel(publicKeySHA1), .synchronizable(),
        ]
        tag.updateMapped({ .applicationTag($0) }, in: &itemAttributes)

        return try CryptoKey.queryOne(keyClass: PK.secKeyClass, itemAttributes: itemAttributes)
    }

    /// Performs a keychain query for a synchronized private ECC key and a given private tag data.
    ///
    /// This function returns an ECC private key instance for the first match found. The type of the returned item has to conform to the ``ECCPrivateKey`` protocol.
    ///
    /// - Attention: Make sure you use unique tag values for Secure Enclave and regular ECC keys.
    /// Saving a Secure Enclave ECC key and a regular ECC key with the same tag may cause undefined behavior when trying to query or delete a key via this tag.
    ///
    /// - Parameters:
    ///   - tag: The private tag data used for the search.
    ///   - accessGroup: Keychain Access group for whith the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///
    /// - Throws: ``KeychainError/ambiguousQueryResult`` if the query returns more than one item for the `tag`.
    /// - Returns: ECC private key instance if the item could be found, `nil` otherwise.
    static func querySynchronizableKey<PK>(
        withTag tag: String,
        accessGroup: String = defaultAccessGroup
    ) throws -> PK? where PK: ECCPrivateKey & CreateableFromSecKey {
        let itemAttributes: Set<ItemAttribute> = [
            .accessGroup(accessGroup), .applicationTag(tag), .synchronizable(),
        ]

        return try CryptoKey.queryOne(keyClass: PK.secKeyClass, itemAttributes: itemAttributes)
    }
}

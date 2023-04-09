// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

public extension Keychain {
    /// Performs a keychain query for a synchronized private RSA key and a given public key.
    ///
    /// This function returns a RSA private key instance for the first match found. The type of the returned item has to conform to the `RSAPrivateKey` protocol.
    ///
    /// - Parameters:
    ///   - publicKey: The RSA public key used to search for the corresponding RSA private key item.
    ///   - tag: The private tag data used for the search.
    ///   - accessGroup: Keychain Access group for whith the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - completion: The completion handler called after the query is completed. This handler is executed on a background thread.
    static func querySynchronizableKey<PK>(
        for publicKey: some RSAPublicKey & PKCS1Convertible,
        withTag tag: String? = nil,
        accessGroup: String = defaultAccessGroup,
        completion: @escaping (Result<PK?, Error>) -> Void
    ) where PK: RSAPrivateKey & CreateableFromSecKey {
        let publicKeySHA1 = Hashing.Insecure.SHA1.hash(publicKey.pkcs1Representation)
        querySynchronizableKey(
            withPublicKeySHA1: publicKeySHA1,
            tag: tag,
            accessGroup: accessGroup,
            completion: completion
        )
    }

    /// Performs a keychain query for a synchronized private RSA key and a given public key digest.
    ///
    /// This function returns a RSA private key instance for the first match found. The type of the returned item has to conform to the ``RSAPrivateKey`` protocol.
    ///
    /// - Parameters:
    ///   - publicKeySHA1: The RSA public key SHA-1 used to search for the corresponding RSA private key item.
    ///   - tag: The private tag data used for the search.
    ///   - accessGroup: Keychain Access group for whith the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - completion: The completion handler called after the query is completed. This handler is executed on a background thread.
    static func querySynchronizableKey<PK>(
        withPublicKeySHA1 publicKeySHA1: Data,
        tag: String? = nil,
        accessGroup: String = defaultAccessGroup,
        completion: @escaping (Result<PK?, Error>) -> Void
    ) where PK: RSAPrivateKey & CreateableFromSecKey {
        var itemAttributes: Set<ItemAttribute> = [
            .applicationLabel(publicKeySHA1), .accessGroup(accessGroup), .synchronizable(),
        ]
        tag.updateMapped({ .applicationTag($0) }, in: &itemAttributes)

        CryptoKey.queryOne(keyClass: PK.secKeyClass, itemAttributes: itemAttributes, completion: completion)
    }

    /// Performs a keychain query for a synchronized private RSA key and a given private tag data.
    ///
    /// This function returns a RSA private key instance for the first match found. The type of the returned item has to conform to the ``RSAPrivateKey`` protocol.
    ///
    /// - Parameters:
    ///   - tag: The private tag data used for the search.
    ///   - accessGroup: Keychain Access group for whith the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - completion: The completion handler called after the query is completed. This handler is executed on a background thread.
    static func querySynchronizableKey<PK>(
        withTag tag: String,
        accessGroup: String = defaultAccessGroup,
        completion: @escaping (Result<PK?, Error>) -> Void
    ) where PK: RSAPrivateKey & CreateableFromSecKey {
        let itemAttributes: Set<ItemAttribute> = [
            .applicationTag(tag), .accessGroup(accessGroup), .synchronizable(),
        ]
        CryptoKey.queryOne(keyClass: PK.secKeyClass, itemAttributes: itemAttributes, completion: completion)
    }

    /// Stores a synchronized RSA private key in the keychain.
    ///
    /// Attempts to store a RSA private key in the keychain. To query the key from the keychain later, you must specify the same `tag`  value and `accessGroup`  that was used when saving.
    ///
    /// - Parameters:
    ///   - privateKey: RSA private key to save in the keychain.
    ///   - tag: The private tag data used for the key.
    ///   - accessGroup: Keychain Access group for which the save should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - accessibility: Access control value of the key. Sets  the conditions under which an app can access the item.
    ///   - label: A keychain item label that can be displayed to the user by apps that have access to the item.
    ///
    /// - Throws: ``KeychainError/itemSavingFailed(status:)`` with a `errSecDuplicateItem` status code if the item already exists in the keychain.
    static func saveSynchronizableKey<PK>(
        _ privateKey: PK,
        withTag tag: String,
        accessGroup: String = defaultAccessGroup,
        accessibility: SynchronizableItemAccessibility = .afterFirstUnlock,
        label: String? = nil
    ) throws where PK: RSAPrivateKey & ConvertibleToSecKey {
        var itemAttributes: Set<ItemAttribute> = [
            .applicationTag(tag), .accessGroup(accessGroup), .synchronizable(accessibility: accessibility),
        ]
        label.updateMapped({ .label($0) }, in: &itemAttributes)

        try CryptoKey.save(keyClass: PK.secKeyClass, secKey: privateKey.secKey, itemAttributes: itemAttributes)
    }

    /// Deletes a synchronized RSA private key from the keychain.
    ///
    /// - Note: No error is thrown if no element with the specified parameters can be found. Instead, the method returns `false` as a return value.
    ///
    /// - Parameters:
    ///   - publicKey: The RSA public key of the private key to delete in the keychain.
    ///   - tag: The private tag data used for the key.
    ///   - accessGroup: Keychain Access group for which the delete should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///
    /// - Returns: `true` if an item matching the parameters was deleted, `false` otherwise.
    @discardableResult
    static func deleteSynchronizablePrivateKey(
        for publicKey: some RSAPublicKey & PKCS1Convertible,
        withTag tag: String,
        accessGroup: String = defaultAccessGroup
    ) throws -> Bool {
        let publicKeySHA1 = Hashing.Insecure.SHA1.hash(publicKey.pkcs1Representation)
        return try deleteSynchronizableKey(
            ofType: Crypto.RSA.PrivateKey.self,
            withTag: tag,
            publicKeySHA1: publicKeySHA1,
            accessGroup: accessGroup
        )
    }

    /// Deletes a synchronized RSA private key from the keychain.
    ///
    /// - Note: No error is thrown if no element with the specified parameters can be found. Instead, the method returns `false` as a return value.
    ///
    /// - Parameters:
    ///   - privateKey: RSA private key to delete in the keychain.
    ///   - tag: The private tag data used for the key.
    ///   - accessGroup: Keychain Access group for which the delete should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///
    /// - Returns: `true` if an item matching the parameters was deleted, `false` otherwise.
    @discardableResult
    static func deleteSynchronizableKey<PK>(
        _ privateKey: PK,
        withTag tag: String,
        accessGroup: String = defaultAccessGroup
    ) throws -> Bool where PK: RSAPrivateKey & PKCS1Convertible {
        let publicKey: Crypto.RSA.PublicKey = privateKey.publicKey()
        let publicKeySHA1 = Hashing.Insecure.SHA1.hash(publicKey.pkcs1Representation)
        return try deleteSynchronizableKey(
            ofType: PK.self,
            withTag: tag,
            publicKeySHA1: publicKeySHA1,
            accessGroup: accessGroup
        )
    }

    /// Deletes any type of synchronized RSA key from the keychain.
    ///
    /// It is recommended to specify the public key hash to disambiguate the query for the key or to make sure that the key tag is unique in the access group.
    /// The deletion behavior is undefined If no public key hash is specified and a second key with the same type and tag exists in the keychain.
    ///
    /// - Note: No error is thrown if no element with the specified parameters can be found. Instead, the method returns `false` as a return value.
    ///
    /// - Parameters:
    ///   - type: Any type of ``RSAKey`` to delete.
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
    ) throws -> Bool where K: RSAKey & DefinesSecKeyClass {
        var itemAttributes: Set<ItemAttribute> = [
            .applicationTag(tag), .accessGroup(accessGroup), .synchronizable(),
        ]
        publicKeySHA1.updateMapped({ .applicationLabel($0) }, in: &itemAttributes)

        return try CryptoKey.delete(keyClass: K.secKeyClass, itemAttributes: itemAttributes)
    }
}

public extension Keychain {
    /// Performs a keychain query for a synchronized private RSA key and a given public key.
    ///
    /// This function returns a RSA private key instance for the first match found. The type of the returned item has to conform to the ``RSAPrivateKey`` protocol.
    ///
    /// - Parameters:
    ///   - publicKey: The RSA public key used to search for the corresponding RSA private key item.
    ///   - tag: The private tag data used for the search.
    ///   - accessGroup: Keychain Access group for whith the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///
    /// - Throws: ``KeychainError/ambiguousQueryResult`` if the query returns more than one item. Use a `tag` value if needed to make the query unique.
    /// - Returns: RSA private key instance if the item could be found, `nil` otherwise.
    static func querySynchronizableKey<PK>(
        for publicKey: some RSAPublicKey & PKCS1Convertible,
        withTag tag: String? = nil,
        accessGroup: String = defaultAccessGroup
    ) throws -> PK? where PK: RSAPrivateKey & CreateableFromSecKey {
        let publicKeySHA1 = Hashing.Insecure.SHA1.hash(publicKey.pkcs1Representation)
        return try querySynchronizableKey(withPublicKeySHA1: publicKeySHA1, tag: tag, accessGroup: accessGroup)
    }

    /// Performs a keychain query for a synchronized private RSA key and a given public key digest.
    ///
    /// This function returns a RSA private key instance for the first match found. The type of the returned item has to conform to the ``RSAPrivateKey`` protocol.
    ///
    /// - Parameters:
    ///   - publicKeySHA1: The RSA public key SHA-1 used to search for the corresponding RSA private key item.
    ///   - tag: The private tag data used for the search.
    ///   - accessGroup: Keychain Access group for whith the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///
    /// - Throws: ``KeychainError/ambiguousQueryResult`` if the query returns more than one item. Use a `tag` value if needed to make the query unique.
    /// - Returns: RSA private key instance if the item could be found, `nil` otherwise.
    static func querySynchronizableKey<PK>(
        withPublicKeySHA1 publicKeySHA1: Data,
        tag: String? = nil,
        accessGroup: String = defaultAccessGroup
    ) throws -> PK? where PK: RSAPrivateKey & CreateableFromSecKey {
        var itemAttributes: Set<ItemAttribute> = [
            .accessGroup(accessGroup), .applicationLabel(publicKeySHA1), .synchronizable(),
        ]
        tag.updateMapped({ .applicationTag($0) }, in: &itemAttributes)

        return try CryptoKey.queryOne(keyClass: PK.secKeyClass, itemAttributes: itemAttributes)
    }

    /// Performs a keychain query for a synchronized private RSA key and a given private tag data.
    ///
    /// This function returns a RSA private key instance for the first match found. The type of the returned item has to conform to the ``RSAPrivateKey`` protocol.
    ///
    /// - Parameters:
    ///   - tag: The private tag data used for the search.
    ///   - accessGroup: Keychain Access group for whith the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///
    /// - Throws: ``KeychainError/ambiguousQueryResult`` if the query returns more than one item for the `tag`.
    /// - Returns: RSA private key instance if the item could be found, `nil` otherwise.
    static func querySynchronizableKey<PK>(
        withTag tag: String,
        accessGroup: String = defaultAccessGroup
    ) throws -> PK? where PK: RSAPrivateKey & CreateableFromSecKey {
        let itemAttributes: Set<ItemAttribute> = [
            .accessGroup(accessGroup), .applicationTag(tag), .synchronizable(),
        ]

        return try CryptoKey.queryOne(keyClass: PK.secKeyClass, itemAttributes: itemAttributes)
    }
}

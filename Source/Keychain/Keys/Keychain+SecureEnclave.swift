// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import LocalAuthentication

public extension Keychain {
    /// Performs a keychain query for a private Secure Enclave key.
    ///
    /// The only keychain items supported by the Secure Enclave are 256-bit elliptic curve private keys
    ///
    /// - Attention: Make sure you use unique tag values for Secure Enclave and regular ECC keys.
    /// Saving a Secure Enclave ECC key and a regular ECC key with the same tag may cause undefined behavior when trying to query or delete a key via this tag.
    ///
    /// - Parameters:
    ///   - tag: The private tag data used for the search.
    ///   - accessGroup: Keychain Access group for whith the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - authentication: Keychain query authentication.
    ///   - completion: The completion handler called after the query is completed. This handler is executed on a background thread.
    static func queryKey<K>(
        withTag tag: String,
        accessGroup: String = defaultAccessGroup,
        authentication: QueryAuthentication = .default,
        completion: @escaping (Result<K?, Error>) -> Void
    ) where K: ECCSecureEnclaveKey & CreateableFromSecKey {
        let itemAttributes: Set<ItemAttribute> = [
            .applicationTag(tag), .accessGroup(accessGroup), .tokenID(kSecAttrTokenIDSecureEnclave as String),
        ]
        CryptoKey.queryOne(keyClass: K.secKeyClass,
                           itemAttributes: itemAttributes,
                           authentication: authentication,
                           completion: completion)
    }

    /// Saves a Secure Enclave key to the keychain.
    ///
    /// Attempts to store a Secure Enclave key in the keychain.
    ///
    /// - Parameters:
    ///   - key: Secure Enclave key to save in the keychain.
    ///   - tag: The private tag data used for the key.
    ///   - accessGroup: Keychain Access group for which the save should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - accessControl: Access control value of the key. Sets the conditions under which an app can access the item.
    ///   - label: A keychain item label that can be displayed to the user by apps that have access to the item.
    ///   - authenticationContext: A local authentication context to use.
    ///
    /// - Throws: An error will be thrown If an ECC private key with the same tag and access group already exists in the keychain.
    static func saveKey<K>(
        _ key: K,
        withTag tag: String,
        accessGroup: String = defaultAccessGroup,
        accessControl: AccessControl = .afterFirstUnlockThisDeviceOnly,
        label: String? = nil,
        authenticationContext: LAContext? = nil
    ) throws where K: ECCSecureEnclaveKey & ConvertibleToSecKey {
        var itemAttributes: Set<ItemAttribute> = [
            .applicationTag(tag), .accessControl(accessControl), .accessGroup(accessGroup),
            .tokenID(kSecAttrTokenIDSecureEnclave as String),
        ]
        label.updateMapped({ .label($0) }, in: &itemAttributes)

        try CryptoKey.save(
            keyClass: K.secKeyClass,
            secKey: key.secKey,
            itemAttributes: itemAttributes,
            authenticationContext: authenticationContext
        )
    }

    /// Deletes a Secure Enclave private key in the keychain.
    ///
    /// - Attention: Make sure you use unique tag values for Secure Enclave and regular ECC keys.
    /// Saving a Secure Enclave ECC key and a regular ECC key with the same tag may cause undefined behavior when trying to query or delete a key via this tag.
    ///
    /// - Note: No error is thrown if no element with the specified parameters can be found. Instead, the method returns `false` as a return value.
    ///
    /// - Parameters:
    ///   - tag: The private tag data used for the search.
    ///   - accessGroup: Keychain Access group for whith the search should be performed. If you don’t explicitly specify a group, the default keychain
    ///   access group will be used.
    ///
    /// - Returns: `true` if an item matching the parameters was deleted, `false` otherwise.
    @discardableResult
    static func deleteSecureEnclaveKey(
        withTag tag: String,
        accessGroup: String = defaultAccessGroup
    ) throws -> Bool {
        let itemAttributes: Set<ItemAttribute> = [
            .applicationTag(tag), .accessGroup(accessGroup), .tokenID(kSecAttrTokenIDSecureEnclave as String),
        ]
        return try CryptoKey.delete(
            keyClass: Crypto.ECC.SecureEnclaveKey.secKeyClass,
            itemAttributes: itemAttributes
        )
    }
}

// MARK: - iOS 13
@available(iOS 13.0, *)
public extension Keychain {
    /// Performs a keychain query for a Secure Enclave key.
    ///
    /// The only keychain items supported by the Secure Enclave are 256-bit elliptic curve private keys
    ///
    /// - Attention: Make sure you use unique tag values for Secure Enclave and regular ECC keys.
    /// Saving a Secure Enclave ECC key and a regular ECC key with the same tag may cause undefined behavior when trying to query or delete a key via this tag.
    ///
    /// - Parameters:
    ///   - tag: The private tag data used for the search.
    ///   - accessGroup: Keychain Access group for whith the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - authentication: Keychain query authentication.
    ///
    /// - Throws: ``KeychainError/ambiguousQueryResult`` if more than one key exists for the specified `tag` in the access group.
    /// - Returns: Secure Enclave key instance if the item could be found, `nil` otherwise.
    static func queryKey<K>(
        withTag tag: String,
        accessGroup: String = defaultAccessGroup,
        authentication: QueryAuthentication = .default
    ) throws -> K? where K: ECCSecureEnclaveKey & CreateableFromSecKey {
        let itemAttributes: Set<ItemAttribute> = [
            .accessGroup(accessGroup), .applicationTag(tag), .tokenID(kSecAttrTokenIDSecureEnclave as String),
        ]

        return try CryptoKey.queryOne(keyClass: K.secKeyClass,
                                      itemAttributes: itemAttributes,
                                      authentication: authentication)
    }

    /// Performs a keychain query for a Secure Enclave key with a given public key digest.
    ///
    /// This function returns a Secure Enclave key instance for the first match found.
    ///
    /// - Parameters:
    ///   - publicKeySHA1: The ECC public key SHA-1 used to search for the corresponding Secure Enclave key item.
    ///   - tag: The private tag data used for the search.
    ///   - accessGroup: Keychain Access group for whith the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - authentication: Keychain query authentication.
    ///
    /// - Throws: ``KeychainError/ambiguousQueryResult`` if no `tag` value for the query was specified and more than one key exists for the specified public key digest in the access group.
    /// - Returns: Secure Enclave key instance if the item could be found, `nil` otherwise.
    static func queryKey<K>(
        withPublicKeySHA1 publicKeySHA1: Data,
        tag: String? = nil,
        accessGroup: String = defaultAccessGroup,
        authentication: QueryAuthentication = .default
    ) throws -> K? where K: ECCSecureEnclaveKey & CreateableFromSecKey {
        var itemAttributes: Set<ItemAttribute> = [
            .applicationLabel(publicKeySHA1), .accessGroup(accessGroup), .tokenID(kSecAttrTokenIDSecureEnclave as String),
        ]
        tag.updateMapped({ .applicationTag($0) }, in: &itemAttributes)

        return try CryptoKey.queryOne(keyClass: K.secKeyClass,
                                      itemAttributes: itemAttributes,
                                      authentication: authentication)
    }

    /// Performs a keychain query for a Secure Enclave key with a given public.
    ///
    /// This function returns a Secure Enclave key instance for the first match found.
    ///
    /// - Parameters:
    ///   - publicKey: The ECC public key used to search for the corresponding Secure Enclave key item.
    ///   - tag: The private tag data used for the search.
    ///   - accessGroup: Keychain Access group for whith the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - authentication: Keychain query authentication.
    ///
    /// - Throws: ``KeychainError/ambiguousQueryResult`` if no `tag` value for the query was specified and more than one key exists for the specified public key in the access group.
    /// - Returns: Secure Enclave key instance if the item could be found, `nil` otherwise.
    static func queryKey<PK, K>(
        for publicKey: PK,
        withTag tag: String? = nil,
        accessGroup: String = Keychain.defaultAccessGroup,
        authentication: Keychain.QueryAuthentication = .default
    ) throws -> K?
        where
        PK: ECCPublicKey,
        K: ECCSecureEnclaveKey & CreateableFromSecKey
    {
        let publicKeySHA1 = Hashing.Insecure.SHA1.hash(publicKey.x963Representation)
        return try queryKey(withPublicKeySHA1: publicKeySHA1, tag: tag, accessGroup: accessGroup, authentication: authentication)
    }
}

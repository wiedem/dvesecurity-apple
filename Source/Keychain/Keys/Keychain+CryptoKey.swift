// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import LocalAuthentication

extension Keychain {
    enum CryptoKey {
        static func queryOne<K>(
            keyClass: SecKeyClass,
            itemAttributes: Set<ItemAttribute> = [],
            authentication: Keychain.QueryAuthentication = .default,
            completion: @escaping (Result<K?, Error>) -> Void
        ) where K: CreateableFromSecKey {
            keyClass.assertAsymmetricKeyClass()

            let query = Keychain.FetchItemsQuery(itemClass: itemClass, returnType: .reference, attributes: itemAttributes)
                .add(keyClass)
                .add(authentication)
            Keychain.queryOneItem(query: query, transform: secKeyResultItemsToKeys, completion: completion)
        }

        static func queryOneSymmetricKey(
            itemAttributes: Set<ItemAttribute> = [],
            authentication: Keychain.QueryAuthentication = .default,
            completion: @escaping (Result<Data?, Error>) -> Void
        ) {
            let query = Keychain.FetchItemsQuery(itemClass: itemClass, returnType: .data, attributes: itemAttributes)
                .add(SecKeyClass.symmetric)
                .add(authentication)
            Keychain.queryOneItem(query: query, completion: completion)
        }

        static func queryOneSymmetricKey<K>(
            itemAttributes: Set<ItemAttribute> = [],
            authentication: Keychain.QueryAuthentication = .default,
            completion: @escaping (Result<K?, Error>) -> Void
        ) where K: RawKeyConvertible {
            let query = Keychain.FetchItemsQuery(itemClass: itemClass, returnType: .data, attributes: itemAttributes)
                .add(SecKeyClass.symmetric)
                .add(authentication)
            Keychain.queryOneItem(query: query, transform: dataResultItemsToKeys, completion: completion)
        }

        static func queryAttributes(
            keyClass: SecKeyClass,
            itemAttributes: Set<ItemAttribute> = [],
            authentication: Keychain.QueryAuthentication = .default,
            completion: @escaping (Result<[String: Any]?, Error>) -> Void
        ) {
            let query = Keychain.FetchItemsQuery(itemClass: itemClass, returnType: .attributes, attributes: itemAttributes)
                .add(keyClass)
                .add(authentication)
            Keychain.queryOneItem(query: query, completion: completion)
        }

        static func save(
            keyClass: SecKeyClass,
            keyData: Data,
            itemAttributes: Set<ItemAttribute> = [],
            authenticationContext: LAContext? = nil
        ) throws {
            let query = Keychain.AddItemQuery(itemClass: itemClass, valueData: keyData, attributes: itemAttributes)
                .add(keyClass)
                .useAuthenticationContext(authenticationContext)
            try Keychain.saveItem(query: query)
        }

        static func save(
            keyClass: SecKeyClass,
            secKey: SecKey,
            itemAttributes: Set<ItemAttribute> = [],
            authenticationContext: LAContext? = nil
        ) throws {
            let query = Keychain.AddItemQuery(secKey: secKey, attributes: itemAttributes)
                .add(keyClass)
                .useAuthenticationContext(authenticationContext)
                .addIsPermanent(true)
            try Keychain.saveItem(query: query)
        }

        static func update(
            keyClass: SecKeyClass,
            newKeyData: Data,
            itemAttributes: Set<ItemAttribute> = [],
            authentication: Keychain.QueryAuthentication = .default
        ) throws {
            let query = Keychain.UpdateItemQuery(itemClass: itemClass, valueData: newKeyData, attributes: itemAttributes)
                .add(keyClass)
                .add(authentication)
            try Keychain.updateItem(query: query)
        }

        @discardableResult
        static func delete(
            keyClass: SecKeyClass,
            itemAttributes: Set<ItemAttribute> = []
        ) throws -> Bool {
            let query = Keychain.DeleteItemsQuery(itemClass: itemClass, attributes: itemAttributes)
                .add(keyClass)
            return try Keychain.deleteItems(query: query)
        }
    }
}

extension Keychain.CryptoKey {
    static let itemClass: Keychain.ItemClass = .key

    static func secKeyResultItemsToKeys<K>(_ result: CFTypeRef) throws -> [K] where K: CreateableFromSecKey {
        guard let secKeyItems = result as? [SecKey] else {
            throw KeychainError.resultError
        }
        return try secKeyItems.map { try K(secKey: $0) }
    }
}

extension Keychain.CryptoKey {
    static func queryAll(
        keyClass: SecKeyClass,
        itemAttributes: Set<Keychain.ItemAttribute> = [],
        limit: UInt = 0,
        authentication: Keychain.QueryAuthentication = .default,
        completion: @escaping (Result<[SecKey]?, Error>) -> Void
    ) {
        keyClass.assertAsymmetricKeyClass()

        let query = Keychain.FetchItemsQuery(itemClass: itemClass, returnType: .reference, attributes: itemAttributes)
            .add(keyClass)
            .add(authentication)
            .setLimit(limit)
        Keychain.queryItems(query: query, completion: completion)
    }

    @available(iOS 13.0, *)
    static func queryAll(
        keyClass: SecKeyClass,
        itemAttributes: Set<Keychain.ItemAttribute> = [],
        limit: UInt = 0,
        authentication: Keychain.QueryAuthentication = .default
    ) throws -> [SecKey]? {
        keyClass.assertAsymmetricKeyClass()

        let query = Keychain.FetchItemsQuery(itemClass: itemClass, returnType: .reference, attributes: itemAttributes)
            .add(keyClass)
            .add(authentication)
            .setLimit(limit)
        return try Keychain.queryItems(query: query)
    }
}

// MARK: - iOS 13
@available(iOS 13.0, *)
extension Keychain.CryptoKey {
    static func queryOne<K>(
        keyClass: SecKeyClass,
        itemAttributes: Set<Keychain.ItemAttribute> = [],
        authentication: Keychain.QueryAuthentication = .default
    ) throws -> K? where K: CreateableFromSecKey {
        keyClass.assertAsymmetricKeyClass()

        let query = Keychain.FetchItemsQuery(itemClass: itemClass, returnType: .reference, attributes: itemAttributes)
            .add(keyClass)
            .add(authentication)
        return try Keychain.queryOneItem(query: query, transform: secKeyResultItemsToKeys)
    }

    static func queryOneSymmetricKey(
        itemAttributes: Set<Keychain.ItemAttribute> = [],
        authentication: Keychain.QueryAuthentication = .default
    ) throws -> Data? {
        let query = Keychain.FetchItemsQuery(itemClass: itemClass, returnType: .data, attributes: itemAttributes)
            .add(SecKeyClass.symmetric)
            .add(authentication)
        return try Keychain.queryOneItem(query: query)
    }

    static func queryAttributes(
        of keyClass: SecKeyClass,
        itemAttributes: Set<Keychain.ItemAttribute> = [],
        authentication: Keychain.QueryAuthentication = .default
    ) throws -> [String: Any]? {
        let query = Keychain.FetchItemsQuery(itemClass: itemClass, returnType: .attributes, attributes: itemAttributes)
            .add(keyClass)
            .add(authentication)
        return try Keychain.queryOneItem(query: query)
    }
}

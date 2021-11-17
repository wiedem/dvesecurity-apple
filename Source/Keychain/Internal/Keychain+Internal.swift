// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

protocol KeychainAttributesConvertible {
    init(attributes: [String: Any])
}

extension Keychain {
    static let dispatchQoSClass: DispatchQoS.QoSClass = .default

    static let asyncDispatchQueue: DispatchQueue = .global(qos: dispatchQoSClass)
}

// MARK: -
extension Keychain {
    static func resultTypeCast<T>(_ result: CFTypeRef) throws -> [T] {
        guard let result = result as? [T] else {
            throw KeychainError.resultError
        }
        return result
    }

    static func dataResultItemsToString(_ result: CFTypeRef) throws -> [String] {
        guard let dataItems = result as? [Data] else {
            throw KeychainError.resultError
        }

        return try dataItems.map {
            guard let string = String(data: $0, encoding: .utf8) else {
                throw KeychainError.resultError
            }
            return string
        }
    }

    static func dataResultItemsToKeys<K>(_ result: CFTypeRef) throws -> [K] where K: RawKeyConvertible {
        guard let dataItems = result as? [Data] else {
            throw KeychainError.resultError
        }
        return try dataItems.map { try K(rawKeyRepresentation: $0) }
    }

    static func attributesTransform<A>(_ result: CFTypeRef) throws -> [A] where A: KeychainAttributesConvertible {
        guard let result = result as? [[String: Any]] else {
            throw KeychainError.resultError
        }
        return result.map { A(attributes: $0) }
    }
}

extension Keychain {
    private static func queryItems<T>(query: CFDictionary, transform: (CFTypeRef) throws -> [T] = resultTypeCast) throws -> [T]? {
        var secItems: CFTypeRef?

        switch SecItemCopyMatching(query, &secItems) {
        case errSecSuccess:
            guard let secItems = secItems else {
                throw KeychainError.resultError
            }
            return try transform(secItems)

        case errSecItemNotFound:
            return nil

        case let status:
            throw KeychainError.itemQueryFailed(status: status)
        }
    }

    static func queryItems<T>(query: KeychainFetchItemsQuery, transform: (CFTypeRef) throws -> [T] = resultTypeCast) throws -> [T]? {
        try queryItems(query: query.queryDictionary as CFDictionary, transform: transform)
    }

    static func queryItems<T>(
        query: KeychainFetchItemsQuery,
        transform: @escaping (CFTypeRef) throws -> [T] = resultTypeCast,
        completion: @escaping (Result<[T]?, Error>) -> Void
    ) {
        Self.asyncDispatchQueue.async {
            let result = Result { () -> [T]? in
                try queryItems(query: query, transform: transform)
            }
            completion(result)
        }
    }

    static func queryOneItem<T>(query: KeychainFetchItemsQuery, transform: (CFTypeRef) throws -> [T] = resultTypeCast) throws -> T? {
        // Set the match limit to two to detect ambiguous results.
        var queryDictionary = query.queryDictionary
        queryDictionary[kSecMatchLimit as String] = 2

        guard let results: [T] = try queryItems(query: queryDictionary as CFDictionary, transform: transform) else {
            return nil
        }
        guard let firstResult = results.first else {
            throw KeychainError.resultError
        }
        guard results.count == 1 else {
            throw KeychainError.ambiguousQueryResult
        }
        return firstResult
    }

    static func queryOneItem<T>(
        query: KeychainFetchItemsQuery,
        transform: @escaping (CFTypeRef) throws -> [T] = resultTypeCast,
        completion: @escaping (Result<T?, Error>) -> Void
    ) {
        Self.asyncDispatchQueue.async {
            let result = Result { () -> T? in
                try queryOneItem(query: query, transform: transform)
            }
            completion(result)
        }
    }
}

extension Keychain {
    static func saveItem(query: KeychainAddItemQuery) throws {
        let queryDictionary = query.queryDictionary as CFDictionary

        let status = SecItemAdd(queryDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.itemSavingFailed(status: status)
        }
    }

    static func updateItem(query: KeychainUpdateItemQuery) throws {
        let queryDictionary = query.queryDictionary as CFDictionary
        let attributesToUpdate = query.updateDictionary as CFDictionary

        let status = SecItemUpdate(queryDictionary, attributesToUpdate)
        guard status == errSecSuccess else {
            throw KeychainError.itemUpdateFailed(status: status)
        }
    }

    @discardableResult
    static func deleteItems(query: KeychainDeleteItemsQuery) throws -> Bool {
        let queryDictionary = query.queryDictionary as CFDictionary

        let status = SecItemDelete(queryDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.itemDeletionFailed(status: status)
        }
        return status == errSecSuccess
    }
}

extension Keychain {
    @discardableResult
    static func deleteItems(query: [String: Any]) throws -> Bool {
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.itemDeletionFailed(status: status)
        }
        return status == errSecSuccess
    }
}

extension Keychain.ItemClass: KeychainQueryParamsConvertible {
    func insertIntoKeychainQuery(_ query: inout [String: Any]) {
        query[kSecClass as String] = secClassString
    }

    var secClassString: String {
        switch self {
        case .internetPassword: return kSecClassInternetPassword as String
        case .genericPassword: return kSecClassGenericPassword as String
        case .certificate: return kSecClassCertificate as String
        case .key: return kSecClassKey as String
        case .identity: return kSecClassIdentity as String
        }
    }
}

// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

extension Keychain {
    final class FetchItemsQuery: KeychainFetchItemsQuery {
        struct ReturnType: OptionSet {
            let rawValue: Int

            static let data = ReturnType(rawValue: 1 << 0)
            static let attributes = ReturnType(rawValue: 1 << 1)
            static let reference = ReturnType(rawValue: 1 << 2)
            static let persistentReference = ReturnType(rawValue: 1 << 3)
        }

        private(set) var queryDictionary = [String: Any]()

        init(itemClass: ItemClass, returnType: ReturnType, attributes: Set<ItemAttribute> = []) {
            insertLimit(0, into: &queryDictionary)

            itemClass.insertIntoKeychainQuery(&queryDictionary)
            returnType.insertIntoKeychainQuery(&queryDictionary)
            attributes.insertIntoKeychainQuery(&queryDictionary)

            // See https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain
            queryDictionary[kSecUseDataProtectionKeychain as String] = true
        }

        func add(_ attributes: some KeychainQueryParamsConvertible) -> Self {
            attributes.insertIntoKeychainQuery(&queryDictionary)
            return self
        }

        func setLimit(_ limit: UInt) -> Self {
            insertLimit(limit, into: &queryDictionary)
            return self
        }

        func includeSynchronizableItems() -> Self {
            queryDictionary[kSecAttrSynchronizable as String] = kSecAttrSynchronizableAny
            return self
        }
    }
}

private extension Keychain.FetchItemsQuery {
    func insertLimit(_ limit: UInt, into attributes: inout [String: Any]) {
        let limitSecValue: Any
        switch limit {
        case 0:
            limitSecValue = kSecMatchLimitAll
        case 1:
            limitSecValue = kSecMatchLimitOne
        default:
            limitSecValue = limit
        }

        attributes[kSecMatchLimit as String] = limitSecValue
    }
}

extension Keychain.FetchItemsQuery.ReturnType: KeychainQueryParamsConvertible {
    func insertIntoKeychainQuery(_ query: inout [String: Any]) {
        if contains(.data) {
            query[kSecReturnData as String] = true
        }
        if contains(.attributes) {
            query[kSecReturnAttributes as String] = true
        }
        if contains(.reference) {
            query[kSecReturnRef as String] = true
        }
        if contains(.persistentReference) {
            query[kSecReturnPersistentRef as String] = true
        }
    }
}

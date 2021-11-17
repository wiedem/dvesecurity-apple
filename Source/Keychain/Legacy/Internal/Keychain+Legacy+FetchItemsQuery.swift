// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

#if os(macOS)
extension Keychain.Legacy {
    struct FetchItemsQuery: KeychainFetchItemsQuery {
        struct ReturnType: OptionSet {
            let rawValue: Int

            static let data = ReturnType(rawValue: 1 << 0)
            static let attributes = ReturnType(rawValue: 1 << 1)
            static let reference = ReturnType(rawValue: 1 << 2)
            static let persistentReference = ReturnType(rawValue: 1 << 3)
        }

        private(set) var queryDictionary = [String: Any]()

        init(
            itemClass: Keychain.ItemClass,
            returnType: ReturnType,
            attributes: Set<Keychain.ItemAttribute> = [],
            keychain: SecKeychain?
        ) {
            insertLimit(0, into: &queryDictionary)

            itemClass.insertIntoKeychainQuery(&queryDictionary)
            returnType.insertIntoKeychainQuery(&queryDictionary)
            attributes.insertIntoKeychainQuery(&queryDictionary)

            if let keychain = keychain {
                queryDictionary[kSecMatchSearchList as String] = [keychain]
            }
        }

        func add<Attributes>(_ attributes: Attributes) -> Self where Attributes: KeychainQueryParamsConvertible {
            var copy = self
            attributes.insertIntoKeychainQuery(&copy.queryDictionary)
            return copy
        }

        func setLimit(_ limit: UInt) -> Self {
            var copy = self
            insertLimit(limit, into: &copy.queryDictionary)
            return copy
        }
    }
}

private extension Keychain.Legacy.FetchItemsQuery {
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

extension Keychain.Legacy.FetchItemsQuery.ReturnType: KeychainQueryParamsConvertible {
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
#endif

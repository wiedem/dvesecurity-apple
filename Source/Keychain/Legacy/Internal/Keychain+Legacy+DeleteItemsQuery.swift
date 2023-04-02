// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

#if os(macOS)
extension Keychain.Legacy {
    struct DeleteItemsQuery: KeychainDeleteItemsQuery {
        private(set) var queryDictionary = [String: Any]()

        init(itemClass: Keychain.ItemClass, attributes: Set<Keychain.ItemAttribute> = [], keychain: SecKeychain?) {
            itemClass.insertIntoKeychainQuery(&queryDictionary)
            attributes.insertIntoKeychainQuery(&queryDictionary)

            if let keychain {
                queryDictionary[kSecMatchSearchList as String] = [keychain]
            }
        }

        func add(_ attributes: some KeychainQueryParamsConvertible) -> Self {
            var copy = self
            attributes.insertIntoKeychainQuery(&copy.queryDictionary)
            return copy
        }

        func includeSynchronizableItems() -> Self {
            var copy = self
            copy.queryDictionary[kSecAttrSynchronizable as String] = kSecAttrSynchronizableAny
            return copy
        }
    }
}
#endif

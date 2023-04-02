// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

extension Keychain {
    struct DeleteItemsQuery: KeychainDeleteItemsQuery {
        private(set) var queryDictionary = [String: Any]()

        init(itemClass: ItemClass, attributes: Set<ItemAttribute> = []) {
            itemClass.insertIntoKeychainQuery(&queryDictionary)
            attributes.insertIntoKeychainQuery(&queryDictionary)

            if #available(iOS 13.0, *) {
                // See https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain
                queryDictionary[kSecUseDataProtectionKeychain as String] = true
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

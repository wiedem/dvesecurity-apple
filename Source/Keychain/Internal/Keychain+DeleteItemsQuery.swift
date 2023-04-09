// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

extension Keychain {
    final class DeleteItemsQuery: KeychainDeleteItemsQuery {
        private(set) var queryDictionary = [String: Any]()

        init(itemClass: ItemClass, attributes: Set<ItemAttribute> = []) {
            itemClass.insertIntoKeychainQuery(&queryDictionary)
            attributes.insertIntoKeychainQuery(&queryDictionary)

            // See https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain
            queryDictionary[kSecUseDataProtectionKeychain as String] = true
        }

        func add(_ attributes: some KeychainQueryParamsConvertible) -> Self {
            attributes.insertIntoKeychainQuery(&queryDictionary)
            return self
        }

        func includeSynchronizableItems() -> Self {
            queryDictionary[kSecAttrSynchronizable as String] = kSecAttrSynchronizableAny
            return self
        }
    }
}

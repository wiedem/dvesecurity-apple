// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

#if os(macOS)
extension Keychain.Legacy {
    final class DeleteItemsQuery: KeychainDeleteItemsQuery {
        private(set) var queryDictionary = [String: Any]()

        init(itemClass: Keychain.ItemClass, attributes: Set<Keychain.ItemAttribute> = [], keychain: SecKeychain?) {
            itemClass.insertIntoKeychainQuery(&queryDictionary)
            attributes.insertIntoKeychainQuery(&queryDictionary)

            if let keychain {
                queryDictionary[kSecMatchSearchList as String] = [keychain]
            }
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
#endif

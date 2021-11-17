// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

extension Keychain {
    struct UpdateItemQuery: KeychainUpdateItemQuery {
        private(set) var queryDictionary = [String: Any]()
        private(set) var updateDictionary = [String: Any]()

        init(itemClass: ItemClass, valueData: Data, attributes: Set<ItemAttribute> = []) {
            itemClass.insertIntoKeychainQuery(&queryDictionary)
            attributes.insertIntoKeychainQuery(&queryDictionary)

            if #available(iOS 13.0, *) {
                // See https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain
                queryDictionary[kSecUseDataProtectionKeychain as String] = true
            }

            updateDictionary[kSecValueData as String] = valueData
        }

        func add<Attributes>(_ attributes: Attributes) -> Self where Attributes: KeychainQueryParamsConvertible {
            var copy = self
            attributes.insertIntoKeychainQuery(&copy.queryDictionary)
            return copy
        }
    }
}

// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

#if os(macOS)
extension Keychain.Legacy {
    struct UpdateItemQuery: KeychainUpdateItemQuery {
        private(set) var queryDictionary = [String: Any]()
        private(set) var updateDictionary = [String: Any]()

        init(itemClass: Keychain.ItemClass, valueData: Data, keychain: SecKeychain?) {
            itemClass.insertIntoKeychainQuery(&queryDictionary)

            if let keychain = keychain {
                queryDictionary[kSecMatchSearchList as String] = [keychain]
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
#endif

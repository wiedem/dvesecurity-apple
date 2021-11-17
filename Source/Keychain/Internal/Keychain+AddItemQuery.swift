// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import LocalAuthentication

extension Keychain {
    struct AddItemQuery: KeychainAddItemQuery {
        private(set) var queryDictionary = [String: Any]()

        init(itemClass: ItemClass, valueData: Data, attributes: Set<ItemAttribute> = []) {
            itemClass.insertIntoKeychainQuery(&queryDictionary)
            attributes.insertIntoKeychainQuery(&queryDictionary)
            queryDictionary[kSecValueData as String] = valueData

            if #available(iOS 13.0, *) {
                // See https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain
                queryDictionary[kSecUseDataProtectionKeychain as String] = true
            }
        }

        init(secKey: SecKey, attributes: Set<ItemAttribute> = []) {
            ItemClass.key.insertIntoKeychainQuery(&queryDictionary)
            attributes.insertIntoKeychainQuery(&queryDictionary)
            queryDictionary[kSecValueRef as String] = secKey

            if #available(iOS 13.0, *) {
                // See https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain
                queryDictionary[kSecUseDataProtectionKeychain as String] = true
            }
        }

        func add<Attributes>(_ attributes: Attributes) -> Self where Attributes: KeychainQueryParamsConvertible {
            var copy = self
            attributes.insertIntoKeychainQuery(&copy.queryDictionary)
            return copy
        }

        func useAuthenticationContext(_ context: LAContext?) -> Self {
            guard let context = context else {
                return self
            }

            var copy = self
            copy.queryDictionary[kSecUseAuthenticationContext as String] = context
            return copy
        }

        func addIsPermanent(_ isPermanent: Bool) -> Self {
            var copy = self
            copy.queryDictionary[kSecAttrIsPermanent as String] = isPermanent
            return copy
        }
    }
}

// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

#if os(macOS)
extension Keychain.Legacy {
    struct AddItemQuery: KeychainAddItemQuery {
        private(set) var queryDictionary = [String: Any]()

        init(
            itemClass: Keychain.ItemClass,
            valueData: Data,
            attributes: Set<Keychain.ItemAttribute> = [],
            keychain: SecKeychain?,
            access: SecAccess?
        ) {
            itemClass.insertIntoKeychainQuery(&queryDictionary)
            attributes.insertIntoKeychainQuery(&queryDictionary)

            queryDictionary[kSecValueData as String] = valueData
            queryDictionary[kSecUseKeychain as String] = keychain
            queryDictionary[kSecAttrAccess as String] = access
        }

        init(
            secKey: SecKey,
            attributes: Set<Keychain.ItemAttribute> = [],
            keychain: SecKeychain?,
            access: SecAccess?
        ) {
            Keychain.ItemClass.key.insertIntoKeychainQuery(&queryDictionary)
            attributes.insertIntoKeychainQuery(&queryDictionary)

            queryDictionary[kSecValueRef as String] = secKey
            queryDictionary[kSecUseKeychain as String] = keychain
            queryDictionary[kSecAttrAccess as String] = access
        }

        func add<Attributes>(_ attributes: Attributes) -> Self where Attributes: KeychainQueryParamsConvertible {
            var copy = self
            attributes.insertIntoKeychainQuery(&copy.queryDictionary)
            return copy
        }

        func addIsPermanent(_ isPermanent: Bool) -> Self {
            var copy = self
            copy.queryDictionary[kSecAttrIsPermanent as String] = isPermanent
            return copy
        }
    }
}
#endif

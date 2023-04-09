// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

#if os(macOS)
extension Keychain.Legacy {
    final class AddItemQuery: KeychainAddItemQuery {
        private(set) var requiresExtendedLifetime: Bool = false
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

        func add(_ attributes: some KeychainQueryParamsConvertible) -> Self {
            attributes.insertIntoKeychainQuery(&queryDictionary)
            return self
        }

        func addIsPermanent(_ isPermanent: Bool) -> Self {
            queryDictionary[kSecAttrIsPermanent as String] = isPermanent
            return self
        }
    }
}
#endif

// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import LocalAuthentication

extension Keychain {
    final class AddItemQuery: KeychainAddItemQuery {
        var requiresExtendedLifetime: Bool { valueData != nil }
        private(set) var queryDictionary = [String: Any]()
        private var valueData: Any?

        init(itemClass: ItemClass, valueData: some SecureData, attributes: Set<ItemAttribute> = []) {
            itemClass.insertIntoKeychainQuery(&queryDictionary)
            attributes.insertIntoKeychainQuery(&queryDictionary)

            // If valueData is a reference type, keep a reference to the value.
            // Otherwise keep a copy of the value.
            // This ensures the data storage is not freed before the query is complete.
            self.valueData = valueData
            let data = valueData.withUnsafeBytes {
                NSData(bytesNoCopy: UnsafeMutableRawPointer(mutating: $0.baseAddress!), length: $0.count, freeWhenDone: false)
            }
            queryDictionary[kSecValueData as String] = data

            // See https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain
            queryDictionary[kSecUseDataProtectionKeychain as String] = true
        }

        init(itemClass: ItemClass, valueData: Data, attributes: Set<ItemAttribute> = []) {
            itemClass.insertIntoKeychainQuery(&queryDictionary)
            attributes.insertIntoKeychainQuery(&queryDictionary)

            queryDictionary[kSecValueData as String] = valueData

            // See https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain
            queryDictionary[kSecUseDataProtectionKeychain as String] = true
        }

        init(secKey: SecKey, attributes: Set<ItemAttribute> = []) {
            ItemClass.key.insertIntoKeychainQuery(&queryDictionary)
            attributes.insertIntoKeychainQuery(&queryDictionary)
            queryDictionary[kSecValueRef as String] = secKey

            // See https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain
            queryDictionary[kSecUseDataProtectionKeychain as String] = true
        }

        deinit {
            valueData = nil
        }

        func add(_ attributes: some KeychainQueryParamsConvertible) -> Self {
            attributes.insertIntoKeychainQuery(&queryDictionary)
            return self
        }

        func useAuthenticationContext(_ context: LAContext?) -> Self {
            guard let context else {
                return self
            }

            queryDictionary[kSecUseAuthenticationContext as String] = context
            return self
        }

        func addIsPermanent(_ isPermanent: Bool) -> Self {
            queryDictionary[kSecAttrIsPermanent as String] = isPermanent
            return self
        }
    }
}

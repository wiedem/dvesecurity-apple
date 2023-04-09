// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

extension Keychain {
    final class UpdateItemQuery: KeychainUpdateItemQuery {
        private(set) var queryDictionary = [String: Any]()
        private(set) var updateDictionary = [String: Any]()

        init(itemClass: ItemClass, valueData: some SecureData, attributes: Set<ItemAttribute> = []) {
            itemClass.insertIntoKeychainQuery(&queryDictionary)
            attributes.insertIntoKeychainQuery(&queryDictionary)

            // See https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain
            queryDictionary[kSecUseDataProtectionKeychain as String] = true

            // TODO: find a better way
            let data = valueData.withUnsafeBytes { rawBufferPointer in
                NSData(bytes: rawBufferPointer.baseAddress, length: valueData.byteCount)
            }
            updateDictionary[kSecValueData as String] = data
        }

        init(itemClass: ItemClass, valueData: Data, attributes: Set<ItemAttribute> = []) {
            itemClass.insertIntoKeychainQuery(&queryDictionary)
            attributes.insertIntoKeychainQuery(&queryDictionary)

            // See https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain
            queryDictionary[kSecUseDataProtectionKeychain as String] = true

            updateDictionary[kSecValueData as String] = valueData
        }

        func add(_ attributes: some KeychainQueryParamsConvertible) -> Self {
            attributes.insertIntoKeychainQuery(&queryDictionary)
            return self
        }
    }
}

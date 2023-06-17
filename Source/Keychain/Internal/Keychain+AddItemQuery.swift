// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import LocalAuthentication

extension Keychain {
    final class AddSecKeyQuery: KeychainAddItemQuery {
        private(set) var queryDictionary: [String: Any]
        private let secKey: SecKey

        init(secKey: SecKey, attributes: Set<ItemAttribute> = []) {
            self.secKey = secKey

            var queryDictionary = [String: Any]()
            ItemClass.key.insertIntoKeychainQuery(&queryDictionary)
            attributes.insertIntoKeychainQuery(&queryDictionary)

            // See https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain
            queryDictionary[kSecUseDataProtectionKeychain as String] = true

            self.queryDictionary = queryDictionary
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

        func queryAttributes(_ queryHandler: ([String: Any]) throws -> Void) rethrows {
            var query = queryDictionary
            query[kSecValueRef as String] = secKey
            try queryHandler(query)
        }
    }
}

extension Keychain {
    final class AddItemQuery<D>: KeychainAddItemQuery where D: SecureData {
        private(set) var queryDictionary: [String: Any]
        private let valueData: D

        init(itemClass: ItemClass, valueData: D, attributes: Set<ItemAttribute> = []) {
            self.valueData = valueData

            var queryDictionary = [String: Any]()
            itemClass.insertIntoKeychainQuery(&queryDictionary)
            attributes.insertIntoKeychainQuery(&queryDictionary)

            // See https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain
            queryDictionary[kSecUseDataProtectionKeychain as String] = true

            self.queryDictionary = queryDictionary
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

        func queryAttributes(_ queryHandler: ([String: Any]) throws -> Void) rethrows {
            try valueData.withUnsafeBytes { bufferPointer in
                let data = NSData(
                    bytesNoCopy: UnsafeMutableRawPointer(mutating: bufferPointer.baseAddress!),
                    length: bufferPointer.count,
                    freeWhenDone: false
                )

                var query = queryDictionary
                query[kSecValueData as String] = data

                try queryHandler(query)
            }
        }
    }
}

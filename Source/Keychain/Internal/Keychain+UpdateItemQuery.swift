// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

extension Keychain {
    final class UpdateItemQuery<D>: KeychainUpdateItemQuery where D: SecureData {
        private(set) var queryDictionary = [String: Any]()
        private let valueData: D

        init(itemClass: ItemClass, valueData: D, attributes: Set<ItemAttribute> = []) {
            itemClass.insertIntoKeychainQuery(&queryDictionary)
            attributes.insertIntoKeychainQuery(&queryDictionary)

            self.valueData = valueData

            // See https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain
            queryDictionary[kSecUseDataProtectionKeychain as String] = true
        }

        func add(_ attributes: some KeychainQueryParamsConvertible) -> Self {
            attributes.insertIntoKeychainQuery(&queryDictionary)
            return self
        }

        func updateAttributes(_ queryHandler: ([String: Any]) throws -> Void) rethrows {
            try valueData.withUnsafeBytes { bufferPointer in
                let data = NSData(
                    bytesNoCopy: UnsafeMutableRawPointer(mutating: bufferPointer.baseAddress!),
                    length: bufferPointer.count,
                    freeWhenDone: false
                )
                let attributes: [String: Any] = [
                    kSecValueData as String: data
                ]

                try queryHandler(attributes)
            }
        }
    }
}

extension Keychain.UpdateItemQuery where D == Crypto.KeyData {
    convenience init(
        itemClass: Keychain.ItemClass,
        transferDataOwnership valueData: NSMutableData,
        attributes: Set<Keychain.ItemAttribute> = []
    ) {
        let valueData = Crypto.KeyData(transferFrom: valueData)
        self.init(itemClass: itemClass, valueData: valueData, attributes: attributes)
    }
}

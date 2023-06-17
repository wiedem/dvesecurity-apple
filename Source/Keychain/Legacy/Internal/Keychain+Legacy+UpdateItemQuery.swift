// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

#if os(macOS)
extension Keychain.Legacy {
    final class UpdateItemQuery<D>: KeychainUpdateItemQuery where D: SecureData {
        private(set) var queryDictionary = [String: Any]()
        private(set) var valueData: D

        init(itemClass: Keychain.ItemClass, valueData: D, keychain: SecKeychain?) {
            itemClass.insertIntoKeychainQuery(&queryDictionary)

            if let keychain {
                queryDictionary[kSecMatchSearchList as String] = [keychain]
            }

            self.valueData = valueData
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
#endif

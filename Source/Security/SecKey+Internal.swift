// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

extension SecKey {
    static func create(keyClass: SecKeyClass, keyData: Data) throws -> SecKey {
        var attributes = [String: Any]()
        keyClass.insertIntoKeychainQuery(&attributes)

        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return secKey
    }

    func externalRepresentation() throws -> Data {
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(self, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        return data
    }
}

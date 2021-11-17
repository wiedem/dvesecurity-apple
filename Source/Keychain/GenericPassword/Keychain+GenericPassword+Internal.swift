// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

extension Keychain.GenericPassword {
    static let itemClass: Keychain.ItemClass = .genericPassword
}

extension Keychain.GenericPassword.Item: KeychainAttributesConvertible {
    init(attributes: [String: Any]) {
        value = attributes[kSecValueData as String] as! Data

        account = attributes[kSecAttrAccount as String] as! String
        service = attributes[kSecAttrService as String] as! String
        modificationDate = attributes[kSecAttrModificationDate as String] as! Date
        creationDate = attributes[kSecAttrCreationDate as String] as! Date
        synchronizable = (attributes[kSecAttrSynchronizable as String] as? NSNumber)?.boolValue == true

        description = attributes[kSecAttrDescription as String] as? String
        comment = attributes[kSecAttrComment as String] as? String
        creator = (attributes[kSecAttrCreator as String] as? NSNumber)?.uint32Value
        label = attributes[kSecAttrLabel as String] as? String
    }
}

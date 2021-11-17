// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

extension Set where Element == Keychain.ItemAttribute {
    // swiftlint:disable:next cyclomatic_complexity function_body_length
    init(secAttributes: [String: Any]) {
        var attributes = [Element]()

        if let accessGroup = secAttributes[kSecAttrAccessGroup as String] as? String {
            attributes.append(.accessGroup(accessGroup))
        }
        if let date = secAttributes[kSecAttrCreationDate as String] as? Date {
            attributes.append(.creationDate(date))
        }
        if let date = secAttributes[kSecAttrModificationDate as String] as? Date {
            attributes.append(.modificationDate(date))
        }
        if let description = secAttributes[kSecAttrDescription as String] as? String {
            attributes.append(.description(description))
        }
        if let comment = secAttributes[kSecAttrComment as String] as? String {
            attributes.append(.description(comment))
        }
        if let creator = secAttributes[kSecAttrCreator as String] as? NSNumber {
            attributes.append(.creator(creator.uint32Value))
        }
        if let label = secAttributes[kSecAttrLabel as String] as? String {
            attributes.append(.label(label))
        }

        if let synchronizable = (secAttributes[kSecAttrSynchronizable as String] as? NSNumber)?.boolValue, synchronizable == true {
            if let secAttrString = secAttributes[kSecAttrAccessible as String] as? String,
               let accessibility = Keychain.SynchronizableItemAccessibility(secAttrString: secAttrString)
            {
                attributes.append(.synchronizable(accessibility: accessibility))
            } else {
                attributes.append(.synchronizable())
            }
        } else {
            // Note that we could get the SecAccessControl instance but we can't get the flags from the instance.
            // Thus we always return an empty set of flags.
            if let secAttrString = secAttributes[kSecAttrAccessible as String] as? String,
               let accessibility = Keychain.ItemAccessibility(secAttrString: secAttrString)
            {
                attributes.append(.accessControl(.init(itemAccessibility: accessibility)))
            }
        }

        if let account = secAttributes[kSecAttrAccount as String] as? String {
            attributes.append(.account(account))
        }
        if let securityDomain = secAttributes[kSecAttrSecurityDomain as String] as? String {
            attributes.append(.securityDomain(securityDomain))
        }
        if let server = secAttributes[kSecAttrServer as String] as? String {
            attributes.append(.server(server))
        }
        if let secAttrString = secAttributes[kSecAttrProtocol as String] as? String,
           let `protocol` = Keychain.InternetPassword.NetworkProtocol(secAttrString: secAttrString)
        {
            attributes.append(.protocol(`protocol`))
        }
        if let secAttrString = secAttributes[kSecAttrAuthenticationType as String] as? String,
           let authenticationType = Keychain.InternetPassword.AuthenticationType(secAttrString: secAttrString)
        {
            attributes.append(.authenticationType(authenticationType))
        }
        if let portNumber = secAttributes[kSecAttrPort as String] as? NSNumber {
            attributes.append(.port(portNumber.uint16Value))
        }
        if let path = secAttributes[kSecAttrPath as String] as? String {
            attributes.append(.path(path))
        }

        if let service = secAttributes[kSecAttrService as String] as? String {
            attributes.append(.service(service))
        }
        if let data = secAttributes[kSecAttrGeneric as String] as? Data {
            attributes.append(.genericData(data))
        }

        if let applicationLabelString = secAttributes[kSecAttrApplicationLabel as String] as? String,
           let applicationLabelData = applicationLabelString.data(using: .utf8)
        {
            attributes.append(.applicationLabel(applicationLabelData))
        } else if let applicationLabelData = secAttributes[kSecAttrApplicationLabel as String] as? Data {
            attributes.append(.applicationLabel(applicationLabelData))
        }
        if let applicationTag = secAttributes[kSecAttrApplicationTag as String] as? String {
            attributes.append(.applicationTag(applicationTag))
        }
        if let keySizeInBits = secAttributes[kSecAttrKeySizeInBits as String] as? Int {
            attributes.append(.keySizeInBits(keySizeInBits))
        }
        if let effectiveKeySize = secAttributes[kSecAttrEffectiveKeySize as String] as? Int {
            attributes.append(.effectiveKeySize(effectiveKeySize))
        }
        if let tokenID = secAttributes[kSecAttrTokenID as String] as? String {
            attributes.append(.tokenID(tokenID))
        }

        self.init(attributes)
    }
}

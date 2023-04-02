// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

extension Keychain {
    enum ItemAttribute: Equatable, Hashable {
        /// The access control of a non synchronizable keychain item.
        ///
        /// See ``Keychain/AccessControl`` for further details.
        case accessControl(AccessControl)
        /// Specifies a value indicating which access group a keychain item is in.
        ///
        /// The access groups that a particular application has membership in are determined by two entitlements for that application.
        /// The application-identifier entitlement contains the application's single access group, unless there is a keychain-access-groups entitlement present. The latter has as its value a list of access groups; the first item in this list is the default access group.
        /// Unless a specific access group is provided when save is called, new items are created in the application's default access group.
        ///
        /// Specifying this attribute in query, update, or delete calls limits the search to the specified access group (of which the calling application must be a member to obtain matching results).
        ///
        /// To share keychain items between multiple applications, each application must have a common group listed in its `keychain-access-groups` entitlement, and each must specify this shared access group name as the value for the access group.
        case accessGroup(String)
        /// The creation date of a keychain item.
        ///
        /// - Note: This value is read-only.
        case creationDate(Date)
        /// The last time a keychain item was updated.
        ///
        /// - Note: This value is read-only
        case modificationDate(Date)
        /// A user-visible string describing the keychain item.
        ///
        /// A user-visible string describing a particular kind of keychain item (e.g., "disk image password").
        case description(String)
        /// A user-editable comment of a keychain item.
        ///
        /// Represents a user-editable comment for a keychain item.
        case comment(String)
        /// The creator of a keychain item.
        ///
        /// This number is the unsigned integer representation of a four-character code (e.g., 'aCrt').
        case creator(UInt32)
        /// A user-visible label for a keychain item.
        ///
        /// A user-visible label for a keychain item which may be used for display purposes.
        ///
        /// Data Protection Keychain entries are usually not visible for the user, so this attribute only matters if an app specifically makes its keychain entries visible to the user.
        ///
        /// Legacy file based keychains (macOS only), on the other hand, can be opened by the user with apps such as the "Keychain Access" app. In this case, this attribute identifies an entry for the user.
        case label(String)
        /// Specifies that an keychain item is synchronizable.
        ///
        /// - Note: The accessibility is only relevant for saving.
        case synchronizable(accessibility: Keychain.SynchronizableItemAccessibility? = nil)
        /// Account name associated with a keychain item.
        ///
        /// Generic and internet password keychain items have this attribute.
        case account(String)
        /// Internet security domain associated with a internet password keychain item.
        ///
        /// Only internet password keychain items have this attribute.
        case securityDomain(String)
        /// Server domain name or IP address associated with a internet password keychain item.
        ///
        /// Only internet password keychain items have this attribute.
        case server(String)
        /// Protocol associated with a internet password keychain item.
        ///
        /// Only internet password keychain items have this attribute.
        /// See ``Keychain/InternetPassword/NetworkProtocol``.
        case `protocol`(InternetPassword.NetworkProtocol)
        /// Authentication scheme associated with a internet password.
        ///
        /// Only internet password keychain items have this attribute.
        /// See ``Keychain/InternetPassword/AuthenticationType``.
        case authenticationType(InternetPassword.AuthenticationType)
        /// Internet port number associated with a internet password.
        ///
        /// Only internet password keychain items have this attribute.
        case port(UInt16)
        /// Path associated with a internet password keychain item.
        ///
        /// Typically the value of this attribute is the path component of the URL for the password item.
        case path(String)
        /// Service name associated with a generic password keychain item.
        ///
        /// Only generic password keychain items have this attribute.
        case service(String)
        /// User defined data associated with a generic password keychain item.
        ///
        /// Only generic password keychain items have this attribute.
        case genericData(Data)
        /// The application label attribute of a `SecKey` keychain item.
        ///
        /// This attribute is used to look up a key programmatically. In particular, for private and public keys, the value of this attribute is the hash of the public key.
        /// Only `SecKey` keychain items have this attribute.
        case applicationLabel(Data)
        /// Private tag data of a `SecKey`.
        ///
        /// Only `SecKey` keychain items have this attribute.
        case applicationTag(String)
        /// The number of bits in a `SecKey` keychain item.
        ///
        /// Only `SecKey` keychain items have this attribute.
        case keySizeInBits(Int)
        /// Attribute indicating the effective number of bits in a `SecKey` keychain item.
        ///
        /// For example, a DES key has a  ``keySizeInBits(_:)`` attribute with a value of 64, but a  ``effectiveKeySize(_:)`` attribute with a value of 56.
        /// Only `SecKey` keychain items have this attribute.
        case effectiveKeySize(Int)
        /// The presence of this attribute indicates that a keychain item is backed by external token.
        ///
        /// The value of this attribute uniquely identifies the containing token. When this attribute is not present, item is stored in the internal keychain database.
        /// Only `SecKey` keychain items have this attribute.
        ///
        /// - Note: Note that once item is created, this attribute cannot be changed - in other words it is not possible to migrate existing items to, from or between tokens.
        /// Currently the only available value for this attribute is `kSecAttrTokenIDSecureEnclave`, which indicates that item (private key) is backed by device's Secure Enclave.
        case tokenID(String)
    }
}

extension Keychain.ItemAttribute: KeychainQueryParamsConvertible {
    // swiftlint:disable:next cyclomatic_complexity function_body_length
    func insertIntoKeychainQuery(_ query: inout [String: Any]) {
        switch self {
        case let .accessControl(accessControl):
            accessControl.insertIntoKeychainQuery(&query)
        case let .accessGroup(group):
            query[kSecAttrAccessGroup as String] = group
        case let .creationDate(date):
            query[kSecAttrCreationDate as String] = date
        case let .modificationDate(date):
            query[kSecAttrModificationDate as String] = date
        case let .description(description):
            query[kSecAttrDescription as String] = description
        case let .comment(comment):
            query[kSecAttrComment as String] = comment
        case let .creator(creator):
            query[kSecAttrCreator as String] = creator
        case let .label(label):
            query[kSecAttrLabel as String] = label
        case let .synchronizable(accessibility):
            if let accessibility {
                query[kSecAttrAccessible as String] = accessibility.secAttrString
            }
            query[kSecAttrSynchronizable as String] = true
        case let .account(account):
            query[kSecAttrAccount as String] = account
        case let .securityDomain(domain):
            query[kSecAttrSecurityDomain as String] = domain
        case let .server(server):
            query[kSecAttrServer as String] = server
        case let .protocol(`protocol`):
            query[kSecAttrProtocol as String] = `protocol`.secAttrString
        case let .authenticationType(authenticationType):
            query[kSecAttrAuthenticationType as String] = authenticationType.secAttrString
        case let .port(port):
            query[kSecAttrPort as String] = port
        case let .path(path):
            query[kSecAttrPath as String] = path
        case let .service(service):
            query[kSecAttrService as String] = service
        case let .genericData(data):
            query[kSecAttrGeneric as String] = data
        case let .applicationLabel(label):
            query[kSecAttrApplicationLabel as String] = label
        case let .applicationTag(tag):
            query[kSecAttrApplicationTag as String] = tag
        case let .keySizeInBits(keySize):
            query[kSecAttrKeySizeInBits as String] = keySize
        case let .effectiveKeySize(keySize):
            query[kSecAttrEffectiveKeySize as String] = keySize
        case let .tokenID(tokenID):
            query[kSecAttrTokenID as String] = tokenID
        }
    }
}

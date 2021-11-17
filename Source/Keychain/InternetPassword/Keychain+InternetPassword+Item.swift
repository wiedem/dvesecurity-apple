// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

public extension Keychain.InternetPassword {
    /// Internet password keychain item.
    ///
    /// Keychain items for internet passwords are returned by the  ``queryItems(account:securityDomain:server:protocol:authenticationType:port:path:accessGroup:authentication:completion:)`` and ``queryItems(account:securityDomain:server:protocol:authenticationType:port:path:accessGroup:authentication:)`` methods.
    struct Item {
        /// The raw password data associated with the internet password keychain item.
        ///
        /// Internet passwords are usually stored using the UTF-8 encoded form of a string.
        ///
        /// - Note: The data is stored encrypted in the keychain and may require you to enter a password when accessing it via a query. After a successful query, the data is available in unencrypted form.
        public let passwordData: Data
        /// Account name associated with a internet password.
        public let account: String
        /// The item's modification date.
        public let modificationDate: Date
        /// The item's creation date.
        public let creationDate: Date
        /// Attribute indicating whether the keychain item can be synchronized to other devices.
        public let synchronizable: Bool

        /// A user-visible label for a keychain item.
        public let label: String?
        /// A user-visible string describing the keychain item.
        public let description: String?
        /// A user-editable comment of a keychain item.
        public let comment: String?
        /// The creator of the keychain item.
        ///
        /// This number is the unsigned integer representation of a four-character code (e.g., 'aCrt').
        public let creator: UInt32?
        /// Internet security domain associated with a internet password keychain item.
        public let securityDomain: String
        /// Server domain name or IP address associated with a internet password keychain item.
        public let server: String
        /// Protocol associated with a internet password keychain item.
        public let `protocol`: Keychain.InternetPassword.NetworkProtocol?
        /// Authentication scheme associated with a internet password.
        public let authenticationType: Keychain.InternetPassword.AuthenticationType?
        /// Internet port number associated with a internet password.
        public let port: UInt16
        /// Path associated with a internet password keychain item.
        ///
        /// Typically the value of this attribute is the path component of the URL for the password item.
        public let path: String
    }
}

public extension Keychain.InternetPassword.Item {
    /// Returns the UTF-8 encoded String representation of the internet password data.
    var password: String {
        String(data: passwordData, encoding: .utf8)!
    }
}

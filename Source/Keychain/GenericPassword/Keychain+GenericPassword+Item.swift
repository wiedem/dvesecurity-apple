// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

public extension Keychain.GenericPassword {
    /// Generic password keychain item.
    ///
    /// Keychain items for generic passwords are returned by the  ``queryItems(account:service:accessGroup:authentication:completion:)`` and ``queryItems(account:service:accessGroup:authentication:)`` methods.
    struct Item {
        /// The raw password data associated with the generic password keychain item.
        public let value: Data
        /// Account name associated with a generic password.
        public let account: String
        /// Service name associated with a generic password keychain item.
        public let service: String
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
    }
}

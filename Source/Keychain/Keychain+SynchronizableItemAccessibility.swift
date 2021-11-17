// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

public extension Keychain {
    /// A type that indicates when a synchronizable keychain item is accessible.
    enum SynchronizableItemAccessibility {
        /// The data in the keychain item can always be accessed regardless of whether the device is locked.
        ///
        /// This is not recommended for application use. Items with this attribute migrate to a new device when using encrypted backups.
        @available(iOS, introduced: 4.0, deprecated: 12.0, message: "Use an accessibility level that provides some user protection, such as afterFirstUnlockThisDeviceOnly")
        case always
        /// The data in the keychain item cannot be accessed after a restart until the device has been unlocked once by the user.
        ///
        /// After the first unlock, the data remains accessible until the next restart. This is recommended for items that need to be accessed by background applications. Items with this attribute migrate to a new device when using encrypted backups.
        case afterFirstUnlock
        /// The data in the keychain item can be accessed only while the device is unlocked by the user.
        ///
        /// This is recommended for items that need to be accessible only while the application is in the foreground. Items with this attribute migrate to a new device when using encrypted backups.
        ///
        /// This is the default value for keychain items added without explicitly setting an accessibility constant.
        case whenUnlocked
    }
}

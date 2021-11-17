// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import LocalAuthentication
import Security

public extension Keychain {
    /// A type that indicates when a keychain item is accessible.
    enum ItemAccessibility {
        /// The data in the keychain item can always be accessed regardless of whether the device is locked.
        ///
        /// This is not recommended for application use. Items with this attribute migrate to a new device when using encrypted backups.
        @available(iOS, introduced: 4.0, deprecated: 12.0, message: "Use an accessibility level that provides some user protection, such as afterFirstUnlockThisDeviceOnly")
        case always
        /// The data in the keychain item cannot be accessed after a restart until the device has been unlocked once by the user.
        ///
        /// After the first unlock, the data remains accessible until the next restart. This is recommended for items that need to be accessed by background applications. Items with this attribute migrate to a new device when using encrypted backups.
        case afterFirstUnlock
        /// The data in the keychain item cannot be accessed after a restart until the device has been unlocked once by the user.
        ///
        /// After the first unlock, the data remains accessible until the next restart. This is recommended for items that need to be accessed by background applications.
        ///
        /// Items with this attribute will not be restored when restoring from a device backup if the device is different from the one in which the item was saved. If it is the same device, the items are restored.
        /// This attribute does not prevent an item from being present in both encrypted and unencrypted device backups.
        case afterFirstUnlockThisDeviceOnly
        /// The data in the keychain can only be accessed when the device is unlocked. Only available if a passcode is set on the device.
        ///
        /// This is recommended for items that only need to be accessible while the application is in the foreground.
        ///
        /// You can only access items with this setting if the device is unlocked.
        ///
        /// Items with this attribute never migrate to a new device. After a backup is restored to a new device, these items are missing. No items can be stored in this class on devices without a passcode. Disabling the device passcode causes all items in this class to be deleted.
        case whenPasscodeSetThisDeviceOnly
        /// The data in the keychain item can always be accessed regardless of whether the device is locked.
        ///
        /// This is not recommended for application use. Items with this attribute do not migrate to a new device. Thus, after restoring from a backup of a different device, these items will not be present.
        @available(iOS, introduced: 4.0, deprecated: 12.0, message: "Use an accessibility level that provides some user protection, such as afterFirstUnlockThisDeviceOnly")
        case alwaysThisDeviceOnly
        /// The data in the keychain item can be accessed only while the device is unlocked by the user.
        ///
        /// This is recommended for items that need to be accessible only while the application is in the foreground. Items with this attribute migrate to a new device when using encrypted backups.
        ///
        /// This is the default value for keychain items added without explicitly setting an accessibility constant.
        case whenUnlocked
        /// The data in the keychain item can be accessed only while the device is unlocked by the user.
        ///
        /// This is recommended for items that need to be accessible only while the application is in the foreground.
        ///
        /// Items with this attribute will not be restored when restoring from a device backup if the device is different from the one in which the item was saved. If it is the same device, the items are restored.
        /// This attribute does not prevent an item from being present in both encrypted and unencrypted device backups.
        case whenUnlockedThisDeviceOnly
    }

    /// A type that contains information about how a keychain item may be used.
    struct AccessControl {
        /// Indicating when a keychain item is accessible.
        public let itemAccessibility: ItemAccessibility

        /// The access control flags of the object that dictate how a keychain item may be used.
        public let flags: AccessControlFlags

        /// Creates a new access control object defining how a keychain item may be used.
        ///
        /// - Parameters:
        ///   - itemAccessibility: Indicating when a keychain item is accessible.
        ///   - flags: The access control flags that dictate how a keychain item may be used.
        public init(itemAccessibility: ItemAccessibility, flags: AccessControlFlags = []) {
            self.itemAccessibility = itemAccessibility
            self.flags = flags
        }
    }
}

// MARK: -
extension Keychain.AccessControl: Hashable {}

public extension Keychain.AccessControl {
    /// Access control with a protection value of `.afterFirstUnlockThisDeviceOnly` and no additional access control flags.
    static let afterFirstUnlockThisDeviceOnly = Keychain.AccessControl(itemAccessibility: .afterFirstUnlockThisDeviceOnly)

    /// Access control with a protection value of `.whenUnlockedThisDeviceOnly` and no additional access control flags.
    static let whenUnlockedThisDeviceOnly = Keychain.AccessControl(itemAccessibility: .whenUnlockedThisDeviceOnly)

    /// Default access control used for Secure Enclave private keys.
    static let defaultSecureEnclaveAccessControl = Keychain.AccessControl(itemAccessibility: .whenUnlockedThisDeviceOnly, flags: [.privateKeyUsage])
}

// MARK: - ProtectionClass CaseIterable
extension Keychain.ItemAccessibility: CaseIterable {
    public static var allCases: [Keychain.ItemAccessibility] {
        return [.afterFirstUnlock, .afterFirstUnlockThisDeviceOnly,
                .whenPasscodeSetThisDeviceOnly, .whenUnlocked, .whenUnlockedThisDeviceOnly,
                .always, .alwaysThisDeviceOnly]
    }
}

// MARK: - LAContext extension
public extension LAContext {
    /// Evaluates an access control object for the specified operation.
    ///
    /// This method asynchronously evaluates an access control. Evaluating an access control may involve prompting the user for various kinds of interaction or
    /// authentication. The actual behavior is dependent on the access control and device type. It can also be affected by installed configuration profiles.
    ///
    /// The localized string you present to the user should provide a clear reason for why you are requesting they authenticate themselves, and what action you will
    /// be taking based on that authentication. This string should be provided in the user’s current language and should be short and clear. It should not contain the
    /// app name, because that appears elsewhere in the authentication dialog. In iOS this appears in the dialog subtitle.
    ///
    /// You should not assume that a previous successful evaluation of an access control necessarily leads to a subsequent successful evaluation. Access control
    /// evaluation can fail for various reasons, including cancelation by the user or the system.
    ///
    /// - Parameters:
    ///   - accessControl: The access control to be evaluated.
    ///   - operation: The operation for the access control to be evaluated. For possible values, see `LAAccessControlOperation`.
    ///   - localizedReason: The app-provided reason for requesting authentication, which displays in the authentication dialog presented to the user.
    ///   - reply: A block that is executed when access control evaluation finishes. This block is evaluated on a private queue internal to the framework in an
    ///   unspecified threading context.
    ///   - result: Result of the policy evaluation
    ///   `.success` if the evaluation  succeeded, otherwise `.failure(error)`.
    ///   See `LAError.Code` for possible error codes
    func evaluateAccessControl(
        _ accessControl: Keychain.AccessControl,
        operation: LAAccessControlOperation,
        localizedReason: String,
        reply: @escaping (_ result: Result<Void, Error>) -> Void
    ) {
        do {
            let accessControl = try accessControl.secAccessControl()
            evaluateAccessControl(accessControl, operation: operation, localizedReason: localizedReason) { _, error in
                if let error = error {
                    reply(.failure(error))
                } else {
                    reply(.success(()))
                }
            }
        } catch {
            DispatchQueue.global().async {
                reply(.failure(error))
            }
        }
    }
}

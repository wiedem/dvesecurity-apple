// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

#if os(macOS)
public extension Keychain {
    /// A container for legacy file based macOS keychain functions.
    ///
    /// This container contains types and functions for the file based keychains of macOS.
    /// Support for keychains of this type is limited.
    /// You should consider using the Data Protection Keychain instead of the file based keychains in macOS.
    ///
    /// - Note: Creating file based keychains is no longer supported as of macOS 12.0 even though the default system keychain may still be used.
    enum Legacy {}
}

public extension Keychain.Legacy {
    /// The status information for a file based keychain.
    struct KeychainStatus: OptionSet {
        public let rawValue: UInt32

        /// Indicates the keychain is unlocked.
        static let unlocked = KeychainStatus(rawValue: kSecUnlockStateStatus)
        /// Indicates the keychain is readable.
        static let readable = KeychainStatus(rawValue: kSecReadPermStatus)
        /// Indicates the keychain is writable.
        static let writable = KeychainStatus(rawValue: kSecWritePermStatus)

        public init(rawValue: UInt32) {
            self.rawValue = rawValue
        }
    }

    /// Returns the default keychain for the application.
    ///
    /// - Throws: ``KeychainError/secError(status:)`` with the status `errSecNoDefaultKeychain` if there is no default keychain for the app.
    /// - Returns: An instance of the default keychain object of type `SecKeychain`.
    static func getDefaultKeychain() throws -> SecKeychain {
        var keychain: SecKeychain!

        let status = SecKeychainCopyDefault(&keychain)
        guard status == errSecSuccess else {
            throw KeychainError.secError(status: status)
        }
        return keychain
    }

    /// Determines the version of keychain services installed on the user’s system.
    ///
    /// - Returns: The version number of keychain services installed on the current system.
    static func getKeychainVersion() throws -> UInt32 {
        var version: UInt32 = 0

        let status = SecKeychainGetVersion(&version)
        guard status == errSecSuccess else {
            throw KeychainError.secError(status: status)
        }
        return version
    }

    /// Retrieves status information of a keychain.
    ///
    /// - Parameter keychain: A keychain object of the keychain whose status you wish to determine for the user session. Pass `nil` to obtain the status of the default keychain.
    ///
    /// - Returns: The status of the specified keychain. See `SecKeychainStatus` for valid status constants.
    static func getKeychainStatus(_ keychain: SecKeychain? = nil) throws -> KeychainStatus {
        var secKeychainStatus = SecKeychainStatus()

        let status = SecKeychainGetStatus(keychain, &secKeychainStatus)
        guard status == errSecSuccess else {
            throw KeychainError.secError(status: status)
        }
        return KeychainStatus(rawValue: secKeychainStatus)
    }

    static func importItem(
        data: Data,
        fileNameOrExtension: String? = nil,
        inputFormat: SecExternalFormat,
        itemType: SecExternalItemType,
        flags: SecItemImportExportFlags,
        keyParams: SecItemImportExportKeyParameters,
        importKeychain: SecKeychain? = nil
    ) throws -> [SecKeychainItem] {
        var items: CFArray?

        var detectedInputFormat = inputFormat
        var detectedItemType = itemType
        var detectedKeyParams = keyParams

        let status = SecItemImport(
            data as CFData,
            fileNameOrExtension as CFString?,
            &detectedInputFormat,
            &detectedItemType,
            flags,
            &detectedKeyParams,
            importKeychain,
            &items
        )

        guard status == errSecSuccess else {
            throw KeychainError.secError(status: status)
        }
        guard let items = items as? [SecKeychainItem] else {
            throw KeychainError.resultError
        }
        return items
    }

    /// Deletes all keychain items of a specific item class from the specified keychain.
    ///
    /// The method deletes all keychain items of a specific item class from the specified keychain.
    /// If no keychain is specified, the default keychain for the application is used.
    ///
    /// - Note: No error is thrown if no elements with the specified parameters can be found. Instead, the method returns `false` as a return value.
    /// - Parameters:
    ///   - itemClass: The type of keychain items which should be deleted.
    ///   - keychain: The keychain on which to perform the operation or `nil` if the default keychain should be used.
    ///
    /// - Returns: `true` if any items of the specified class were deleted from the specified keychain, `false` otherwise.
    @discardableResult
    static func deleteAllItems(
        ofClass itemClass: Keychain.ItemClass,
        inKeychain keychain: SecKeychain? = nil
    ) throws -> Bool {
        let query = Keychain.Legacy.DeleteItemsQuery(itemClass: itemClass, keychain: keychain)
            .includeSynchronizableItems()
        return try Keychain.deleteItems(query: query)
    }
}

@available(macOS, deprecated: 12.0)
public extension Keychain.Legacy {
    /// Sets the default file based keychain for the application.
    ///
    /// See [SecKeychainSetDefault](https://developer.apple.com/documentation/security/1393097-seckeychainsetdefault) for further details.
    ///
    /// - Parameter keychain: A reference to the keychain to be set as default.
    static func setDefaultKeychain(_ keychain: SecKeychain) throws {
        let status = SecKeychainSetDefault(keychain)
        guard status == errSecSuccess else {
            throw KeychainError.secError(status: status)
        }
    }

    /// Creates an empty file based keychain.
    ///
    /// - Parameters:
    ///   - pathName: A string representing the POSIX path indicating where to store the keychain.
    ///   - password: The password which is used to protect the new keychain.
    ///
    /// - Returns: The keychain object of type `SecKeychain` for the created keychain.
    static func createKeychain(pathName: String, password: String) throws -> SecKeychain {
        var keychain: SecKeychain!

        let status = SecKeychainCreate(pathName, UInt32(password.count), password, false, nil, &keychain)
        guard status == errSecSuccess else {
            throw KeychainError.secError(status: status)
        }
        return keychain
    }

    /// Opens a file based keychain.
    ///
    /// - Parameter pathName: A string representing the POSIX path to the keychain to open.
    ///
    /// - Returns: The keychain object of type `SecKeychain` for the created keychain.
    static func openKeychain(pathName: String) throws -> SecKeychain {
        var keychain: SecKeychain!

        let status = SecKeychainOpen(pathName, &keychain)
        guard status == errSecSuccess else {
            throw KeychainError.secError(status: status)
        }
        return keychain
    }

    /// Deletes a keychain from the default keychain search list, and removes the keychain itself if it is a file.
    ///
    /// - Parameter secKeychain: A keychain object you wish to delete.
    static func deleteKeychain(_ keychain: SecKeychain) throws {
        let status = SecKeychainDelete(keychain)
        guard status == errSecSuccess else {
            throw KeychainError.secError(status: status)
        }
    }

    /// Locks a file based keychain.
    ///
    /// Your application should not call this function unless you are responding to a user’s request to lock a keychain. In general, you should leave the keychain unlocked so that the user does not have to unlock it again in another application.
    ///
    /// - Parameter secKeychain: A reference to the keychain you wish to lock.
    static func lockKeychain(_ keychain: SecKeychain) throws {
        let status = SecKeychainLock(keychain)
        guard status == errSecSuccess else {
            throw KeychainError.secError(status: status)
        }
    }

    /// Locks all file based keychains belonging to the current user.
    ///
    /// Your application should not call this function unless you are responding to a user’s request to lock a keychain. In general, you should leave the keychain unlocked so that the user does not have to unlock it again in another application.
    static func lockAllKeychains() throws {
        let status = SecKeychainLockAll()
        guard status == errSecSuccess else {
            throw KeychainError.secError(status: status)
        }
    }

    /// Unlocks a file based keychain.
    ///
    /// - Parameters:
    ///   - secKeychain: A reference to the keychain you wish to unlock.
    ///   - password: The password for the keychain. If you pass `nil` this function displays the Unlock Keychain dialog to prompt the user for the keychain password.
    static func unlockKeychain(_ keychain: SecKeychain, password: String?) throws {
        let passwordLength: UInt32 = password != nil ? UInt32(password!.count) : 0
        let status = SecKeychainUnlock(keychain, passwordLength, password, password != nil)
        guard status == errSecSuccess else {
            throw KeychainError.secError(status: status)
        }
    }
}
#endif

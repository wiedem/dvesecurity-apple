// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

/// A container for keychain types and methods.
public enum Keychain {
    /// Keychain access groups of the application.
    ///
    /// The list of keychain access groups of the application. It is guaranteed that this list will never be empty if the application has an application ID.
    /// See ``defaultAccessGroup``.
    ///
    /// - Note: macOS applications may not have an application ID in which case they don't have access to the Data Protection Keychain.
    /// Trying to access this property in such an application will cause your app to crash with a fatal error.
    public static let accessGroups: [String] = {
        let accessGroups = AppEntitlements.keychainAccessGroups
        guard accessGroups.isEmpty == false else {
            return [AppEntitlements.applicationIdentifier]
        }
        return accessGroups
    }()

    /// Default keychain access group of the application.
    ///
    /// The default keychain access group is either the first entry of the keychain access groups, or the application ID when the app has no keychain groups.
    ///
    /// - Note: macOS applications may not have an application ID in which case they don't have access to the Data Protection Keychain.
    /// Trying to access this property in such an application will cause your app to crash with a fatal error.
    public static let defaultAccessGroup = accessGroups[0]

    /// Deletes all keychain items of a specific item class from an access group.
    ///
    /// The method deletes all keychain items of a specific item class from an access group.
    ///
    /// - Note: No error is thrown if no elements with the specified parameters can be found. Instead, the method returns `false` as a return value.
    /// - Note: This function also deletes synchronizable items.
    /// - Parameters:
    ///   - itemClass: The type of keychain items which should be deleted.
    ///   - accessGroup: Keychain access group from which the items should be deleted. The ``defaultAccessGroup`` is used if no value is specified.
    ///
    /// - Returns: `true` if any items of the specified class were deleted from the access group, `false` otherwise.
    @discardableResult
    public static func deleteAllItems(
        ofClass itemClass: ItemClass,
        inAccessGroup accessGroup: String = Keychain.defaultAccessGroup
    ) throws -> Bool {
        let itemAttributes: Set<ItemAttribute> = [.accessGroup(accessGroup)]
        let query = Keychain.DeleteItemsQuery(itemClass: itemClass, attributes: itemAttributes)
            .includeSynchronizableItems()
        return try Keychain.deleteItems(query: query)
    }

    /// Deletes all keychain items of a specific item class from the specified access groups.
    ///
    /// The method deletes all keychain items of a specific item class from the specified access groups.
    ///
    /// - Note: No error is thrown if no elements with the specified parameters can be found. Instead, the method returns `false` as a return value.
    /// - Note: This function also deletes synchronizable items.
    /// - Parameters:
    ///   - itemClass: The type of keychain items which should be deleted.
    ///   - accessGroups: The list of keychain access groups from which the items should be deleted.
    ///
    /// - Returns: `true` if any items of the specified class were deleted from the specified access groups, `false` otherwise.
    @discardableResult
    public static func deleteAllItems(
        ofClass itemClass: ItemClass,
        inAccessGroups accessGroups: [String]
    ) throws -> Bool {
        var itemsDeleted = false
        try accessGroups.forEach {
            itemsDeleted = try deleteAllItems(ofClass: itemClass, inAccessGroup: $0) || itemsDeleted
        }
        return itemsDeleted
    }
}

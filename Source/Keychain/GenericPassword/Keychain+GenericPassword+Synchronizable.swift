// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import LocalAuthentication

public extension Keychain.GenericPassword {
    /// Searches the keychain for a synchronizable generic password.
    ///
    /// - Parameters:
    ///   - account: Specifies the account name for the password.
    ///   - service: Specifies the service associated with the password.
    ///   - accessGroup: Keychain Access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///
    /// - Returns: The generic password decoded as a `String` value, or `nil` if no item was found.
    class func querySynchronizable(
        forAccount account: String,
        service: String,
        accessGroup: String = Keychain.defaultAccessGroup
    ) throws -> String? {
        let itemAttributes: Set<Keychain.ItemAttribute> = [
            .account(account), .service(service), .accessGroup(accessGroup), .synchronizable(),
        ]

        let query = Keychain.FetchItemsQuery(itemClass: itemClass, returnType: .data, attributes: itemAttributes)
        return try Keychain.queryOneItem(query: query, transform: Keychain.dataResultItemsToString)
    }

    /// Asynchronously searches the keychain for a synchronizable generic password.
    ///
    /// - Parameters:
    ///   - account: Specifies the account name for the password.
    ///   - service: Specifies the service associated with the password.
    ///   - accessGroup: Keychain Access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - completion: The completion handler called after the query is completed. This handler is executed on a background thread.
    class func querySynchronizable(
        forAccount account: String,
        service: String,
        accessGroup: String = Keychain.defaultAccessGroup,
        completion: @escaping (Result<String?, Error>) -> Void
    ) {
        let itemAttributes: Set<Keychain.ItemAttribute> = [
            .account(account), .service(service), .accessGroup(accessGroup), .synchronizable(),
        ]

        let query = Keychain.FetchItemsQuery(itemClass: itemClass, returnType: .data, attributes: itemAttributes)
        Keychain.queryOneItem(query: query, transform: Keychain.dataResultItemsToString, completion: completion)
    }

    /// Saves a synchronizable generic password to the keychain for a specific account and service with a specific access control.
    ///
    /// The synchronizable entry in the keychain is uniquely identified by the account name and the associated service.
    ///
    /// - Parameters:
    ///   - password: Specifies the password to save.
    ///   - account: Specifies the account name for the password.
    ///   - service: Specifies the service associated with the password.
    ///   - accessGroup: Keychain Access group for which the save should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - accessibility: Indicates when your application needs access to an item's data. You should choose the most restrictive option that meets your application's needs to allow the system to protect that item in the best way possible.
    ///   - label: A keychain item label that can be displayed to the user by apps that have access to the item.
    class func saveSynchronizable(
        _ password: String,
        forAccount account: String,
        service: String,
        accessGroup: String = Keychain.defaultAccessGroup,
        accessibility: Keychain.SynchronizableItemAccessibility = .afterFirstUnlock,
        label: String? = nil
    ) throws {
        guard let data = password.data(using: .utf8) else {
            throw Keychain.GenericPasswordError.invalidPassword
        }
        var itemAttributes: Set<Keychain.ItemAttribute> = [
            .account(account),
            .service(service),
            .accessGroup(accessGroup),
            .synchronizable(accessibility: accessibility),
        ]
        label.updateMapped({ .label($0) }, in: &itemAttributes)

        let query = Keychain.AddItemQuery(itemClass: itemClass, valueData: data, attributes: itemAttributes)
        try Keychain.saveItem(query: query)
    }

    /// Updates a synchronizable generic password in the keychain for a specific account and service.
    ///
    /// The synchronizable entry in the keychain is uniquely identified by the account name and the associated service.
    ///
    /// - Parameters:
    ///   - newPassword: Specifies the new password to update to.
    ///   - account: Specifies the account name for this password.
    ///   - service: Specifies the service associated with this password.
    ///   - accessGroup: Keychain Access group for which the update should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    class func updateSynchronizable(
        newPassword: String,
        forAccount account: String,
        service: String,
        accessGroup: String = Keychain.defaultAccessGroup
    ) throws {
        guard let data = newPassword.data(using: .utf8) else {
            throw Keychain.GenericPasswordError.invalidPassword
        }
        let itemAttributes: Set<Keychain.ItemAttribute> = [
            .account(account), .service(service), .accessGroup(accessGroup), .synchronizable(),
        ]

        let query = Keychain.UpdateItemQuery(itemClass: itemClass, valueData: data, attributes: itemAttributes)
        try Keychain.updateItem(query: query)
    }

    /// Updates or saves a synchronizable generic password in the keychain for a specific account and service.
    ///
    /// The synchronizable entry in the keychain is uniquely identified by the account name and the associated service.
    ///
    /// - Parameters:
    ///   - password: Specifies the new password to be saved or updated to.
    ///   - account: Specifies the account name for this password.
    ///   - service: Specifies the service associated with this password.
    ///   - accessGroup: Keychain Access group for which the upsert should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - accessibility: Indicates when your application needs access to an item's data. You should choose the most restrictive option that meets your application's needs to allow the system to protect that item in the best way possible.
    ///   This parameter is only used for saving the password and not for updating the password.
    ///   - label: A keychain item label that can be displayed to the user by apps that have access to the item. This parameter is only used for saving the password and not for updating the password.
    class func upsertSynchronizable(
        _ password: String,
        forAccount account: String,
        service: String,
        accessGroup: String = Keychain.defaultAccessGroup,
        accessibility: Keychain.SynchronizableItemAccessibility = .afterFirstUnlock,
        label: String? = nil
    ) throws {
        do {
            try saveSynchronizable(password, forAccount: account, service: service, accessGroup: accessGroup, accessibility: accessibility, label: label)
        } catch let KeychainError.itemSavingFailed(status) where status == errSecDuplicateItem {
            try updateSynchronizable(newPassword: password, forAccount: account, service: service, accessGroup: accessGroup)
        } catch {
            throw error
        }
    }

    /// Deletes a synchronizable generic password in the keychain for a specific account and service.
    ///
    /// The synchronizable entry in the keychain is uniquely identified by the account name and the associated service.
    ///
    /// - Note: No error is thrown if no element with the specified parameters can be found. Instead, the method returns `false` as a return value.
    ///
    /// - Parameters:
    ///   - account: Specifies the account name for this password.
    ///   - service: Specifies the service associated with this password
    ///   - accessGroup: Keychain Access group for which the delete should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///
    /// - Returns: `true` if an item matching the parameters was deleted, `false` otherwise.
    @discardableResult
    class func deleteSynchronizable(
        forAccount account: String,
        service: String,
        accessGroup: String = Keychain.defaultAccessGroup
    ) throws -> Bool {
        let itemAttributes: Set<Keychain.ItemAttribute> = [
            .account(account), .service(service), .accessGroup(accessGroup), .synchronizable(),
        ]

        let query = Keychain.DeleteItemsQuery(itemClass: itemClass, attributes: itemAttributes)
        return try Keychain.deleteItems(query: query)
    }
}

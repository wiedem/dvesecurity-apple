// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import LocalAuthentication

extension Keychain {
    /// An error that occurs during keychain operations with a generic password.
    public enum GenericPasswordError: Error {
        /// An indication that the specified data cannot be used as a generic password.
        case invalidPassword
    }

    /// A container for generic password items.
    open class GenericPassword {
        /// Queries generic password items in an access group.
        ///
        /// This method queries generic password entries, including synchronizable entries, in the keychain and returns them as an array of ``Item`` items.
        ///
        /// - Parameters:
        ///   - account: Specifies the account value with which to restrict the query.
        ///   - service: Specifies the service value with which to restrict the query.
        ///   - accessGroup: Keychain Access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
        ///   - authentication: Keychain query authentication.
        ///   - completion: The completion handler called after the query is completed. This handler is executed on a background thread.
        open class func queryItems(
            account: String? = nil,
            service: String? = nil,
            accessGroup: String = defaultAccessGroup,
            authentication: QueryAuthentication = .default,
            completion: @escaping (Result<[Item]?, Error>) -> Void
        ) {
            var itemAttributes: Set<Keychain.ItemAttribute> = [.accessGroup(accessGroup)]
            account.updateMapped({ .account($0) }, in: &itemAttributes)
            service.updateMapped({ .service($0) }, in: &itemAttributes)

            let query = Keychain.FetchItemsQuery(
                itemClass: itemClass,
                returnType: [.data, .attributes],
                attributes: itemAttributes
            )
            .add(authentication)
            .includeSynchronizableItems()

            Keychain.queryItems(query: query, transform: attributesTransform, completion: completion)
        }

        /// Searches the keychain for a generic password.
        ///
        /// Searches the keychain for a generic non-synchronizable password and returns the entry as a value of `String`.
        ///
        /// Returns a ``KeychainError/resultError`` if the value of the entry cannot be decoded to a String.
        ///
        /// - Parameters:
        ///   - account: Specifies the account name for the password.
        ///   - service: Specifies the service associated with the password.
        ///   - accessGroup: Keychain Access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
        ///   - authentication: Keychain query authentication.
        ///   - completion: The completion handler called after the query is completed. This handler is executed on a background thread.
        open class func query(
            forAccount account: String,
            service: String,
            accessGroup: String = defaultAccessGroup,
            authentication: QueryAuthentication = .default,
            completion: @escaping (Result<String?, Error>) -> Void
        ) {
            let itemAttributes: Set<Keychain.ItemAttribute> = [
                .account(account), .service(service), .accessGroup(accessGroup),
            ]

            let query = Keychain.FetchItemsQuery(itemClass: itemClass, returnType: .data, attributes: itemAttributes)
                .add(authentication)
            Keychain.queryOneItem(query: query, transform: Keychain.dataResultItemsToString, completion: completion)
        }

        /// Adds a generic password to the keychain.
        ///
        /// Saves a non-synchronizable generic password as an UTF-8 encoded string in the keychain for a specific account and service with a specific access control.
        ///
        /// An entry for the specified account and service must not yet exist in the keychain, otherwise the error ``KeychainError/itemSavingFailed(status:)``  will be thrown with a status code value `errSecDuplicateItem`.
        ///
        /// - Parameters:
        ///   - password: Specifies the password to save.
        ///   - account: Specifies the account name for the password.
        ///   - service: Specifies the service associated with the password.
        ///   - accessGroup: Keychain Access group for which the save should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
        ///   - accessControl: Indicates when your application needs access to an item's data. You should choose the most restrictive option that meets your application's needs to allow the system to protect that item in the best way possible.
        ///   - label: A keychain item label that can be displayed to the user by apps that have access to the item.
        ///   - authenticationContext: A local authentication context to use.
        open class func save(
            _ password: String,
            forAccount account: String,
            service: String,
            accessGroup: String = defaultAccessGroup,
            accessControl: AccessControl = .afterFirstUnlockThisDeviceOnly,
            label: String? = nil,
            authenticationContext: LAContext? = nil
        ) throws {
            guard let data = password.data(using: .utf8) else {
                throw Keychain.GenericPasswordError.invalidPassword
            }
            var itemAttributes: Set<Keychain.ItemAttribute> = [
                .account(account), .service(service), .accessGroup(accessGroup), .accessControl(accessControl),
            ]
            label.updateMapped({ .label($0) }, in: &itemAttributes)

            let query = Keychain.AddItemQuery(itemClass: itemClass, valueData: data, attributes: itemAttributes)
                .useAuthenticationContext(authenticationContext)
            try Keychain.saveItem(query: query)
        }

        /// Updates a generic password in the keychain.
        ///
        /// Updates the value of a non-synchronizable generic password in the keychain with the UTF-8 encoded value of the specified string for a specific account and service.
        ///
        /// - Parameters:
        ///   - newPassword: Specifies the new password to update to.
        ///   - account: Specifies the account name for the password.
        ///   - service: Specifies the service associated with the password.
        ///   - accessGroup: Keychain Access group for which the update should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
        ///   - authentication: Keychain query authentication.
        open class func update(
            newPassword: String,
            forAccount account: String,
            service: String,
            accessGroup: String = defaultAccessGroup,
            authentication: QueryAuthentication = .default
        ) throws {
            guard let data = newPassword.data(using: .utf8) else {
                throw Keychain.GenericPasswordError.invalidPassword
            }
            let itemAttributes: Set<Keychain.ItemAttribute> = [
                .account(account), .service(service), .accessGroup(accessGroup),
            ]

            let query = Keychain.UpdateItemQuery(itemClass: itemClass, valueData: data, attributes: itemAttributes)
                .add(authentication)
            try Keychain.updateItem(query: query)
        }

        /// Updates or saves a generic password in the keychain.
        ///
        /// Adds a new non-synchronizable generic password to the keychain identified by the specified account and service if no such entry already exists.
        /// If such an entry already exists, the value of the entry will be updated with the UTF-8 encoded value of the specified password.
        ///
        /// - Parameters:
        ///   - password: Specifies the new password to be saved or updated to.
        ///   - account: Specifies the account name for the password.
        ///   - service: Specifies the service associated with the password.
        ///   - accessGroup: Keychain Access group for which the upsert should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
        ///   - accessControl: Indicates when your application needs access to an item's data. You should choose the most restrictive option that meets your application's needs to allow the system to protect that item in the best way possible.
        ///   This parameter is only used for saving the password and not for updating the password.
        ///   - label: A keychain item label that can be displayed to the user by apps that have access to the item.
        ///   - authentication: Keychain query authentication. This parameter is only used for updating the password and not for saving the password.
        open class func upsert(
            _ password: String,
            forAccount account: String,
            service: String,
            accessGroup: String = defaultAccessGroup,
            accessControl: AccessControl = .afterFirstUnlockThisDeviceOnly,
            label: String? = nil,
            authentication: QueryAuthentication = .default
        ) throws {
            do {
                try save(password, forAccount: account, service: service, accessGroup: accessGroup, accessControl: accessControl, label: label)
            } catch let KeychainError.itemSavingFailed(status) where status == errSecDuplicateItem {
                try update(newPassword: password, forAccount: account, service: service, accessGroup: accessGroup, authentication: authentication)
            } catch {
                throw error
            }
        }

        /// Deletes a generic password in the keychain.
        ///
        /// Deletes a non-sychronizable generic password identified by the specified account and service in the keychain.
        ///
        /// - Note: No error is thrown if no entry for the account can be found. Instead, the method returns `false` as a return value.
        ///
        /// - Parameters:
        ///   - account: Specifies the account name for the password.
        ///   - service: Specifies the service associated with the password
        ///   - accessGroup: Keychain Access group for which the delete should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
        ///
        /// - Returns: `true` if an item matching the parameters was deleted, `false` otherwise.
        @discardableResult
        open class func delete(
            forAccount account: String,
            service: String,
            accessGroup: String = defaultAccessGroup
        ) throws -> Bool {
            let itemAttributes: Set<Keychain.ItemAttribute> = [
                .account(account), .service(service), .accessGroup(accessGroup),
            ]

            let query = Keychain.DeleteItemsQuery(itemClass: itemClass, attributes: itemAttributes)
            return try Keychain.deleteItems(query: query)
        }
    }
}

@available(iOS 13.0, *)
extension Keychain.GenericPassword {
    /// Queries generic password items in an access group.
    ///
    /// This method queries generic password entries, including synchronizable entries, in the keychain and returns them as an array of ``Item`` items.
    ///
    /// - Parameters:
    ///   - account: Specifies the account value with which to restrict the query.
    ///   - service: Specifies the service value with which to restrict the query.
    ///   - accessGroup: Keychain Access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - authentication: Keychain query authentication.
    ///
    /// - Returns: A list of  generic password items of type ``Item``, or `nil` if no item was found.
    public class func queryItems(
        account: String? = nil,
        service: String? = nil,
        accessGroup: String = Keychain.defaultAccessGroup,
        authentication: Keychain.QueryAuthentication = .default
    ) throws -> [Item]? {
        var itemAttributes: Set<Keychain.ItemAttribute> = [.accessGroup(accessGroup)]
        account.updateMapped({ .account($0) }, in: &itemAttributes)
        service.updateMapped({ .service($0) }, in: &itemAttributes)

        let query = Keychain.FetchItemsQuery(
            itemClass: itemClass,
            returnType: [.data, .attributes],
            attributes: itemAttributes
        )
        .add(authentication)
        .includeSynchronizableItems()

        return try Keychain.queryItems(query: query, transform: Keychain.attributesTransform)
    }

    /// Searches the keychain for a generic password.
    ///
    /// Searches the keychain for a generic non-synchronizable password and returns the entry as a value of `String`.
    ///
    /// - Parameters:
    ///   - account: Specifies the account name for the password.
    ///   - service: Specifies the service associated with the password.
    ///   - accessGroup: Keychain Access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - authentication: Keychain query authentication.
    ///
    /// - Throws: ``KeychainError/resultError`` if the value of the entry cannot be decoded to a String.
    /// - Returns: The generic password decoded as a `String` value, or `nil` if no item was found.
    public class func query(
        forAccount account: String,
        service: String,
        accessGroup: String = Keychain.defaultAccessGroup,
        authentication: Keychain.QueryAuthentication = .default
    ) throws -> String? {
        let itemAttributes: Set<Keychain.ItemAttribute> = [
            .account(account), .service(service), .accessGroup(accessGroup),
        ]

        let query = Keychain.FetchItemsQuery(itemClass: itemClass, returnType: .data, attributes: itemAttributes)
            .add(authentication)
        return try Keychain.queryOneItem(query: query, transform: Keychain.dataResultItemsToString)
    }
}

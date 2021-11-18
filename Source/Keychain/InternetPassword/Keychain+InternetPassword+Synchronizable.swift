// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

extension Keychain.InternetPassword {
    /// Searches the keychain for a single synchronizable internet password entry.
    ///
    /// Searches the keychain for a single synchronizable internet password item of the access group identified by a unqiue combination of the `account`, `security domain`, `server`, `protocol`, `authentication type`, `port` and `path` fields.
    ///
    /// Since all fields except the `account` are optional, you must ensure that the specified combination of fields identifies a unique entry.
    /// If the query returns more than one item a ``KeychainError/ambiguousQueryResult``error result will be returned.
    ///
    /// Use the ``Keychain/InternetPassword/queryItems(account:securityDomain:server:protocol:authenticationType:port:path:accessGroup:authentication:completion:)`` or ``Keychain/InternetPassword/queryItems(account:securityDomain:server:protocol:authenticationType:port:path:accessGroup:authentication:)`` method and filter the results with the ``Keychain/InternetPassword/Item/synchronizable`` field if you want to use a query which may return multiple items.
    ///
    /// - Parameters:
    ///   - account: Specifies the account name for the password.
    ///   - accessGroup: Keychain Access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - securityDomain: The internet security domain associated with the password item.
    ///   - server: Server domain name or IP address associated with the password item.
    ///   - protocol: Protocol associated with the internet password item.
    ///   - authenticationType: Authentication scheme associated with the internet password item.
    ///   - port: Internet port number associated with the internet password item.
    ///   - path: Path associated with the internet password keychain item.
    ///   - completion: The completion handler called after the query is completed. This handler is executed on a background thread.
    open class func queryOneSynchronizable(
        forAccount account: String,
        accessGroup: String = Keychain.defaultAccessGroup,
        securityDomain: String? = nil,
        server: String? = nil,
        protocol: Keychain.InternetPassword.NetworkProtocol? = nil,
        authenticationType: Keychain.InternetPassword.AuthenticationType? = nil,
        port: UInt16? = nil,
        path: String? = nil,
        completion: @escaping (Result<String?, Error>) -> Void
    ) {
        var itemAttributes: Set<Keychain.ItemAttribute> = [
            .account(account), .accessGroup(accessGroup), .synchronizable(),
        ]
        securityDomain.updateMapped({ .securityDomain($0) }, in: &itemAttributes)
        server.updateMapped({ .server($0) }, in: &itemAttributes)
        `protocol`.updateMapped({ .protocol($0) }, in: &itemAttributes)
        authenticationType.updateMapped({ .authenticationType($0) }, in: &itemAttributes)
        port.updateMapped({ .port($0) }, in: &itemAttributes)
        path.updateMapped({ .path($0) }, in: &itemAttributes)

        let query = Keychain.FetchItemsQuery(itemClass: itemClass, returnType: .data, attributes: itemAttributes)
        Keychain.queryOneItem(query: query, transform: Keychain.dataResultItemsToString, completion: completion)
    }

    /// Adds a synchronizable internet password to the keychain.
    ///
    /// Saves a synchronizable internet password in the keychain for a specific account and with the given fields.
    ///
    /// An entry for the specified account must not yet exist in the keychain, otherwise the error ``KeychainError/itemSavingFailed(status:)``  will be thrown with a status code value `errSecDuplicateItem`.
    ///
    /// - Note: Internet passwords are uniquely identified in the keychain by a combination of the `account`, `security domain`, `server`, `protocol`, `authentication type`, `port` and `path` fields.
    /// I.e. these fields are primary keys and affect how you can uniquely identify and query an item.
    ///
    /// - Parameters:
    ///   - password: Specifies the password to save.
    ///   - account: Specifies the account name for this password.
    ///   - accessGroup: Keychain Access group for which the save should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - securityDomain: The internet security domain associated with the password item.
    ///   - server: Server domain name or IP address associated with the password item.
    ///   - protocol: Protocol associated with the internet password item.
    ///   - authenticationType: Authentication scheme associated with the internet password item.
    ///   - port: Internet port number associated with the internet password item.
    ///   - path: Path associated with the internet password keychain item.
    ///   - accessibility: Indicates when your application needs access to an item's data.  You should choose the most restrictive option that meets your application's needs to allow the system to protect that item in the best way possible.
    ///   - label: A keychain item label that can be displayed to the user by apps that have access to the item. This parameter is only used for saving the password and not for updating the password.
    open class func saveSynchronizable(
        _ password: String,
        forAccount account: String,
        accessGroup: String = Keychain.defaultAccessGroup,
        securityDomain: String? = nil,
        server: String? = nil,
        protocol: Keychain.InternetPassword.NetworkProtocol? = nil,
        authenticationType: Keychain.InternetPassword.AuthenticationType? = nil,
        port: UInt16? = nil,
        path: String? = nil,
        accessibility: Keychain.SynchronizableItemAccessibility = .afterFirstUnlock,
        label: String? = nil
    ) throws {
        guard let data = password.data(using: .utf8) else {
            throw Keychain.InternetPasswordError.invalidPassword
        }
        var itemAttributes: Set<Keychain.ItemAttribute> = [
            .account(account), .accessGroup(accessGroup), .synchronizable(accessibility: accessibility),
        ]
        securityDomain.updateMapped({ .securityDomain($0) }, in: &itemAttributes)
        server.updateMapped({ .server($0) }, in: &itemAttributes)
        `protocol`.updateMapped({ .protocol($0) }, in: &itemAttributes)
        authenticationType.updateMapped({ .authenticationType($0) }, in: &itemAttributes)
        port.updateMapped({ .port($0) }, in: &itemAttributes)
        path.updateMapped({ .path($0) }, in: &itemAttributes)
        label.updateMapped({ .label($0) }, in: &itemAttributes)

        let query = Keychain.AddItemQuery(itemClass: itemClass, valueData: data, attributes: itemAttributes)
        try Keychain.saveItem(query: query)
    }

    /// Updates synchronizable internet password items in the keychain.
    ///
    /// Searches and updates synchronizable internet password items in the keychain of the access group identified by a combination of the `account`, `security domain`, `server`, `protocol`, `authentication type`, `port` and `path` fields.
    ///
    /// - Important: This method may update one or more keychain items depending on the combination of specified fields.
    /// If only a single entry is to be updated, you must ensure that the combination of fields uniquely identifies an entry.
    ///
    /// - Parameters:
    ///   - newPassword: Specifies the new password to update to.
    ///   - account: Specifies the account name for this password.
    ///   - accessGroup: Keychain Access group for which the update should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - securityDomain: The internet security domain associated with the password item.
    ///   - server: Server domain name or IP address associated with the password item.
    ///   - protocol: Protocol associated with the internet password item.
    ///   - authenticationType: Authentication scheme associated with the internet password item.
    ///   - port: Internet port number associated with the internet password item.
    ///   - path: Path associated with the internet password keychain item.
    open class func updateSynchronizableItems(
        newPassword: String,
        forAccount account: String,
        accessGroup: String = Keychain.defaultAccessGroup,
        securityDomain: String? = nil,
        server: String? = nil,
        protocol: Keychain.InternetPassword.NetworkProtocol? = nil,
        authenticationType: Keychain.InternetPassword.AuthenticationType? = nil,
        port: UInt16? = nil,
        path: String? = nil
    ) throws {
        guard let data = newPassword.data(using: .utf8) else {
            throw Keychain.InternetPasswordError.invalidPassword
        }
        var itemAttributes: Set<Keychain.ItemAttribute> = [
            .account(account), .accessGroup(accessGroup), .synchronizable(),
        ]
        securityDomain.updateMapped({ .securityDomain($0) }, in: &itemAttributes)
        server.updateMapped({ .server($0) }, in: &itemAttributes)
        `protocol`.updateMapped({ .protocol($0) }, in: &itemAttributes)
        authenticationType.updateMapped({ .authenticationType($0) }, in: &itemAttributes)
        port.updateMapped({ .port($0) }, in: &itemAttributes)
        path.updateMapped({ .path($0) }, in: &itemAttributes)

        let query = Keychain.UpdateItemQuery(itemClass: itemClass, valueData: data, attributes: itemAttributes)
        return try Keychain.updateItem(query: query)
    }

    /// Updates or saves a synchronizable internet password in the keychain for a specific account.
    ///
    /// The synchronizable entry in the keychain is uniquely identified by the account name.
    ///
    /// - Parameters:
    ///   - password: Specifies the new password to be saved or updated to.
    ///   - account: Specifies the account name for this password.
    ///   - accessGroup: Keychain Access group for which the upsert should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - securityDomain: The internet security domain associated with the password item.
    ///   - server: Server domain name or IP address associated with the password item.
    ///   - protocol: Protocol associated with the internet password item.
    ///   - authenticationType: Authentication scheme associated with the internet password item.
    ///   - port: Internet port number associated with the internet password item.
    ///   - path: Path associated with the internet password keychain item.
    ///   - accessibility: Indicates when your application needs access to an item's data.  You should choose the most restrictive option that meets your application's needs to allow the system to protect that item in the best way possible. This parameter is only used for saving the password and not for updating the password.
    ///   - label: A keychain item label that can be displayed to the user by apps that have access to the item. This parameter is only used for saving the password and not for updating the password.
    open class func upsertSynchronizable(
        _ password: String,
        forAccount account: String,
        accessGroup: String = Keychain.defaultAccessGroup,
        securityDomain: String? = nil,
        server: String? = nil,
        protocol: Keychain.InternetPassword.NetworkProtocol? = nil,
        authenticationType: Keychain.InternetPassword.AuthenticationType? = nil,
        port: UInt16? = nil,
        path: String? = nil,
        accessibility: Keychain.SynchronizableItemAccessibility = .afterFirstUnlock,
        label: String? = nil
    ) throws {
        do {
            try saveSynchronizable(password,
                                   forAccount: account,
                                   accessGroup: accessGroup,
                                   securityDomain: securityDomain,
                                   server: server,
                                   protocol: `protocol`,
                                   authenticationType: authenticationType,
                                   port: port,
                                   path: path,
                                   accessibility: accessibility,
                                   label: label)
        } catch let KeychainError.itemSavingFailed(status) where status == errSecDuplicateItem {
            try updateSynchronizableItems(newPassword: password,
                                          forAccount: account,
                                          accessGroup: accessGroup,
                                          securityDomain: securityDomain,
                                          server: server,
                                          protocol: `protocol`,
                                          authenticationType: authenticationType,
                                          port: port,
                                          path: path)
        } catch {
            throw error
        }
    }

    /// Deletes synchronizable internet password items in the keychain.
    ///
    /// Searches and deletes synchronizable internet password items in the keychain of the access group identified by a combination of the `account`, `security domain`, `server`, `protocol`, `authentication type`, `port` and `path` fields.
    ///
    /// - Warning: This method may delete one or more keychain items depending on the combination of specified fields.
    /// If only a single entry is to be deleted, you must ensure that the combination of fields uniquely identifies an entry.
    ///
    /// - Parameters:
    ///   - account: Specifies the account name for the password.
    ///   - accessGroup: Keychain Access group for which the delete should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - securityDomain: The internet security domain associated with the password item.
    ///   - server: Server domain name or IP address associated with the password item.
    ///   - protocol: Protocol associated with the internet password item.
    ///   - authenticationType: Authentication scheme associated with the internet password item.
    ///   - port: Internet port number associated with the internet password item.
    ///   - path: Path associated with the internet password keychain item.
    ///
    /// - Returns: `true` if at least one item in the keychain was deleted, `false` otherwise.
    @discardableResult
    open class func deleteSynchronizableItems(
        forAccount account: String,
        accessGroup: String = Keychain.defaultAccessGroup,
        securityDomain: String? = nil,
        server: String? = nil,
        protocol: Keychain.InternetPassword.NetworkProtocol? = nil,
        authenticationType: Keychain.InternetPassword.AuthenticationType? = nil,
        port: UInt16? = nil,
        path: String? = nil
    ) throws -> Bool {
        var itemAttributes: Set<Keychain.ItemAttribute> = [
            .account(account), .accessGroup(accessGroup), .synchronizable(),
        ]
        securityDomain.updateMapped({ .securityDomain($0) }, in: &itemAttributes)
        server.updateMapped({ .server($0) }, in: &itemAttributes)
        `protocol`.updateMapped({ .protocol($0) }, in: &itemAttributes)
        authenticationType.updateMapped({ .authenticationType($0) }, in: &itemAttributes)
        port.updateMapped({ .port($0) }, in: &itemAttributes)
        path.updateMapped({ .path($0) }, in: &itemAttributes)

        let query = Keychain.DeleteItemsQuery(itemClass: itemClass, attributes: itemAttributes)
        return try Keychain.deleteItems(query: query)
    }
}

@available(iOS 13.0, *)
extension Keychain.InternetPassword {
    /// Searches the keychain for a single synchronizable internet password entry.
    ///
    /// Searches the keychain for a single synchronizable internet password item of the access group identified by a unqiue combination of the `account`, `security domain`, `server`, `protocol`, `authentication type`, `port` and `path` fields.
    ///
    /// Since all fields except the `account` are optional, you must ensure that the specified combination of fields identifies a unique entry.
    ///
    /// Use the ``Keychain/InternetPassword/queryItems(account:securityDomain:server:protocol:authenticationType:port:path:accessGroup:authentication:completion:)`` or ``Keychain/InternetPassword/queryItems(account:securityDomain:server:protocol:authenticationType:port:path:accessGroup:authentication:)`` method and filter the results with the ``Keychain/InternetPassword/Item/synchronizable`` attribute if you want to use a query which may return multiple items.
    ///
    /// - Parameters:
    ///   - account: Specifies the account name for the password.
    ///   - accessGroup: Keychain Access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - securityDomain: The internet security domain associated with the password item.
    ///   - server: Server domain name or IP address associated with the password item.
    ///   - protocol: Protocol associated with the internet password item.
    ///   - authenticationType: Authentication scheme associated with the internet password item.
    ///   - port: Internet port number associated with the internet password item.
    ///   - path: Path associated with the internet password keychain item.
    ///
    /// - Throws: ``KeychainError/ambiguousQueryResult`` if the query returns more than one item.
    /// - Returns: The password, or nil if no password was found for this account.
    open class func queryOneSynchronizable(
        forAccount account: String,
        accessGroup: String = Keychain.defaultAccessGroup,
        securityDomain: String? = nil,
        server: String? = nil,
        protocol: Keychain.InternetPassword.NetworkProtocol? = nil,
        authenticationType: Keychain.InternetPassword.AuthenticationType? = nil,
        port: UInt16? = nil,
        path: String? = nil
    ) throws -> String? {
        var itemAttributes: Set<Keychain.ItemAttribute> = [
            .account(account), .accessGroup(accessGroup), .synchronizable(),
        ]
        securityDomain.updateMapped({ .securityDomain($0) }, in: &itemAttributes)
        server.updateMapped({ .server($0) }, in: &itemAttributes)
        `protocol`.updateMapped({ .protocol($0) }, in: &itemAttributes)
        authenticationType.updateMapped({ .authenticationType($0) }, in: &itemAttributes)
        port.updateMapped({ .port($0) }, in: &itemAttributes)
        path.updateMapped({ .path($0) }, in: &itemAttributes)

        let query = Keychain.FetchItemsQuery(itemClass: itemClass, returnType: .data, attributes: itemAttributes)
        return try Keychain.queryOneItem(query: query, transform: Keychain.dataResultItemsToString)
    }
}

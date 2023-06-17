// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import LocalAuthentication

extension Keychain {
    /// An error that occurs during keychain operations with a internet password.
    public enum InternetPasswordError: Error {
        /// An indication that the specified data cannot be used as a internet password.
        case invalidPassword
    }

    /// A container for internet password items.
    public enum InternetPassword {
        /// Queries internet password items in an access group.
        ///
        /// This method queries Internet password entries in the keychain, including synchronizable entries, and returns them as an array of  ``Item`` items.
        ///
        /// - Parameters:
        ///   - account: Specifies the account value with which to restrict the query.
        ///   - service: Specifies the service value with which to restrict the query.
        ///   - server: Specifies the server value with which to restrict the query.
        ///   - protocol: Specifies the protocol value with which to restrict the query.
        ///   - authenticationType: Specifies the authenticationType value with which to restrict the query.
        ///   - port: Specifies the port value with which to restrict the query.
        ///   - path: Specifies the path value with which to restrict the query.
        ///   - accessGroup: Keychain Access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
        ///   - authentication: Keychain query authentication.
        ///
        /// - Returns: A list of  internet password items of type ``Item``, or `nil` if no item was found.
        public static func queryItems(
            forAccount account: String? = nil,
            securityDomain: String? = nil,
            server: String? = nil,
            protocol: Keychain.InternetPassword.NetworkProtocol? = nil,
            authenticationType: Keychain.InternetPassword.AuthenticationType? = nil,
            port: UInt16? = nil,
            path: String? = nil,
            accessGroup: String = Keychain.defaultAccessGroup,
            authentication: Keychain.QueryAuthentication = .default
        ) throws -> [Item]? {
            var itemAttributes: Set<Keychain.ItemAttribute> = [.accessGroup(accessGroup)]
            account.updateMapped({ .account($0) }, in: &itemAttributes)
            securityDomain.updateMapped({ .securityDomain($0) }, in: &itemAttributes)
            server.updateMapped({ .server($0) }, in: &itemAttributes)
            `protocol`.updateMapped({ .protocol($0) }, in: &itemAttributes)
            authenticationType.updateMapped({ .authenticationType($0) }, in: &itemAttributes)
            port.updateMapped({ .port($0) }, in: &itemAttributes)
            path.updateMapped({ .path($0) }, in: &itemAttributes)

            let query = Keychain.FetchItemsQuery(
                itemClass: itemClass,
                returnType: [.data, .attributes],
                attributes: itemAttributes
            )
            .add(authentication)
            .includeSynchronizableItems()

            return try Keychain.queryItems(query: query, transform: Keychain.attributesTransform)
        }

        /// Asynchronously queries internet password items in an access group.
        ///
        /// This method queries Internet password entries in the keychain, including synchronizable entries, and returns them as an array of  ``Item`` items.
        ///
        /// - Parameters:
        ///   - account: Specifies the account value with which to restrict the query.
        ///   - service: Specifies the service value with which to restrict the query.
        ///   - server: Specifies the server value with which to restrict the query.
        ///   - protocol: Specifies the protocol value with which to restrict the query.
        ///   - authenticationType: Specifies the authenticationType value with which to restrict the query.
        ///   - port: Specifies the port value with which to restrict the query.
        ///   - path: Specifies the path value with which to restrict the query.
        ///   - accessGroup: Keychain Access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
        ///   - authentication: Keychain query authentication.
        ///   - completion: The completion handler called after the query is completed. This handler is executed on a background thread.
        public static func queryItems(
            forAccount account: String? = nil,
            securityDomain: String? = nil,
            server: String? = nil,
            protocol: Keychain.InternetPassword.NetworkProtocol? = nil,
            authenticationType: Keychain.InternetPassword.AuthenticationType? = nil,
            port: UInt16? = nil,
            path: String? = nil,
            accessGroup: String = defaultAccessGroup,
            authentication: QueryAuthentication = .default,
            completion: @escaping (Result<[Item]?, Error>) -> Void
        ) {
            var itemAttributes: Set<Keychain.ItemAttribute> = [.accessGroup(accessGroup)]
            account.updateMapped({ .account($0) }, in: &itemAttributes)
            securityDomain.updateMapped({ .securityDomain($0) }, in: &itemAttributes)
            server.updateMapped({ .server($0) }, in: &itemAttributes)
            `protocol`.updateMapped({ .protocol($0) }, in: &itemAttributes)
            authenticationType.updateMapped({ .authenticationType($0) }, in: &itemAttributes)
            port.updateMapped({ .port($0) }, in: &itemAttributes)
            path.updateMapped({ .path($0) }, in: &itemAttributes)

            let query = Keychain.FetchItemsQuery(
                itemClass: itemClass,
                returnType: [.data, .attributes],
                attributes: itemAttributes
            )
            .add(authentication)
            .includeSynchronizableItems()

            Keychain.queryItems(query: query, transform: attributesTransform, completion: completion)
        }

        /// Searches the keychain for a single internet password entry.
        ///
        /// Searches the keychain for a single non-synchronizable internet password item of the access group identified by a unqiue combination of the `account`, `security domain`, `server`, `protocol`, `authentication type`, `port` and `path` fields.
        ///
        /// - Parameters:
        ///   - account: Specifies the account name for this password.
        ///   - accessGroup: Keychain Access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
        ///   - securityDomain: The internet security domain associated with the password item.
        ///   - server: Server domain name or IP address associated with the password item.
        ///   - protocol: Protocol associated with the internet password item.
        ///   - authenticationType: Authentication scheme associated with the internet password item.
        ///   - port: Internet port number associated with the internet password item.
        ///   - path: Path associated with the internet password keychain item.
        ///   - authentication: Keychain query authentication used for the search operation.
        ///
        /// - Throws: ``KeychainError/ambiguousQueryResult`` if the query returns more than one item.
        /// - Returns: The password for the specified account and service, or `nil` if no item was found.
        public static func queryOne(
            forAccount account: String,
            accessGroup: String = Keychain.defaultAccessGroup,
            securityDomain: String? = nil,
            server: String? = nil,
            protocol: NetworkProtocol? = nil,
            authenticationType: AuthenticationType? = nil,
            port: UInt16? = nil,
            path: String? = nil,
            authentication: Keychain.QueryAuthentication = .default
        ) throws -> String? {
            var itemAttributes: Set<Keychain.ItemAttribute> = [
                .account(account), .accessGroup(accessGroup),
            ]
            securityDomain.updateMapped({ .securityDomain($0) }, in: &itemAttributes)
            server.updateMapped({ .server($0) }, in: &itemAttributes)
            `protocol`.updateMapped({ .protocol($0) }, in: &itemAttributes)
            authenticationType.updateMapped({ .authenticationType($0) }, in: &itemAttributes)
            port.updateMapped({ .port($0) }, in: &itemAttributes)
            path.updateMapped({ .path($0) }, in: &itemAttributes)

            let query = Keychain.FetchItemsQuery(itemClass: itemClass, returnType: .data, attributes: itemAttributes)
                .add(authentication)
            return try Keychain.queryOneItem(query: query, transform: Keychain.dataResultItemsToString)
        }

        /// Asynchronously searches the keychain for a single internet password entry.
        ///
        /// Searches the keychain for a single non-synchronizable internet password item of the access group identified by a unqiue combination of the `account`, `security domain`, `server`, `protocol`, `authentication type`, `port` and `path` fields.
        ///
        /// - Parameters:
        ///   - account: Specifies the account name for this password.
        ///   - accessGroup: Keychain Access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
        ///   - securityDomain: The internet security domain associated with the password item.
        ///   - server: Server domain name or IP address associated with the password item.
        ///   - protocol: Protocol associated with the internet password item.
        ///   - authenticationType: Authentication scheme associated with the internet password item.
        ///   - port: Internet port number associated with the internet password item.
        ///   - path: Path associated with the internet password keychain item.
        ///   - authentication: Keychain query authentication used for the search operation.
        ///   - completion: The completion handler called after the query is completed. This handler is executed on a background thread.
        public static func queryOne(
            forAccount account: String,
            accessGroup: String = defaultAccessGroup,
            securityDomain: String? = nil,
            server: String? = nil,
            protocol: InternetPassword.NetworkProtocol? = nil,
            authenticationType: InternetPassword.AuthenticationType? = nil,
            port: UInt16? = nil,
            path: String? = nil,
            authentication: QueryAuthentication = .default,
            completion: @escaping (Result<String?, Error>) -> Void
        ) {
            var itemAttributes: Set<Keychain.ItemAttribute> = [
                .account(account), .accessGroup(accessGroup),
            ]
            securityDomain.updateMapped({ .securityDomain($0) }, in: &itemAttributes)
            server.updateMapped({ .server($0) }, in: &itemAttributes)
            `protocol`.updateMapped({ .protocol($0) }, in: &itemAttributes)
            authenticationType.updateMapped({ .authenticationType($0) }, in: &itemAttributes)
            port.updateMapped({ .port($0) }, in: &itemAttributes)
            path.updateMapped({ .path($0) }, in: &itemAttributes)

            let query = Keychain.FetchItemsQuery(itemClass: itemClass, returnType: .data, attributes: itemAttributes)
                .add(authentication)
            Keychain.queryOneItem(query: query, transform: dataResultItemsToString, completion: completion)
        }

        /// Adds an internet password to the keychain.
        ///
        /// Saves a non-synchronizable internet password in the keychain for a specific account and with the given fields.
        ///
        /// An entry for the specified account must not yet exist in the keychain, otherwise the error ``KeychainError/itemSavingFailed(status:)``  will be thrown with a status code value `errSecDuplicateItem`.
        ///
        /// - Note: Internet passwords are uniquely identified in the keychain by a combination of the `account`, `security domain`, `server`, `protocol`, `authentication type`, `port` and `path` fields.
        /// I.e. these fields are primary keys and affect how you can uniquely identify and query an item.
        ///
        /// - Parameters:
        ///   - password: The password to save.
        ///   - account: The unique account name for the password item.
        ///   - accessGroup: Keychain Access group for which the save should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
        ///   - securityDomain: The internet security domain associated with the password item.
        ///   - server: Server domain name or IP address associated with the password item.
        ///   - protocol: Protocol associated with the internet password item.
        ///   - authenticationType: Authentication scheme associated with the internet password item.
        ///   - port: Internet port number associated with the internet password item.
        ///   - path: Path associated with the internet password keychain item.
        ///   - accessControl: Indicates when your application needs access to an item's data.  You should choose the most restrictive option that meets your application's needs to allow the system to protect that item in the best way possible.
        ///   - label: A keychain item label that can be displayed to the user by apps that have access to the item.
        ///   - authenticationContext: A local authentication context to use.
        public static func save(
            _ password: String,
            forAccount account: String,
            accessGroup: String = defaultAccessGroup,
            securityDomain: String = "",
            server: String = "",
            protocol: InternetPassword.NetworkProtocol? = nil,
            authenticationType: InternetPassword.AuthenticationType? = nil,
            port: UInt16 = 0,
            path: String = "",
            accessControl: AccessControl = .afterFirstUnlockThisDeviceOnly,
            label: String? = nil,
            authenticationContext: LAContext? = nil
        ) throws {
            guard let valueData = Crypto.KeyData(copyFrom: password as NSString, encoding: .utf8) else {
                throw Keychain.InternetPasswordError.invalidPassword
            }

            var itemAttributes: Set<Keychain.ItemAttribute> = [
                .account(account), .accessGroup(accessGroup), .securityDomain(securityDomain),
                .server(server), .port(port), .path(path),
                .accessControl(accessControl),
            ]
            `protocol`.updateMapped({ .protocol($0) }, in: &itemAttributes)
            authenticationType.updateMapped({ .authenticationType($0) }, in: &itemAttributes)
            label.updateMapped({ .label($0) }, in: &itemAttributes)

            let query = Keychain.AddItemQuery(
                itemClass: itemClass,
                valueData: valueData,
                attributes: itemAttributes
            )
            .useAuthenticationContext(authenticationContext)

            try Keychain.saveItem(query: query)
        }

        /// Updates internet password items in the keychain.
        ///
        /// Searches and updates non-synchronizable internet password items in the keychain of the access group identified by a combination of the `account`, `security domain`, `server`, `protocol`, `authentication type`, `port` and `path` fields.
        ///
        /// - Important: This method may update one or more keychain items depending on the combination of specified fields.
        /// If only a single entry is to be updated, you must ensure that the combination of fields uniquely identifies an entry.
        ///
        /// - Parameters:
        ///   - newPassword: The new password value of the keychain item.
        ///   - account: The account name for the password.
        ///   - accessGroup: Keychain Access group for which the update should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
        ///   - securityDomain: The internet security domain associated with the password item.
        ///   - server: Server domain name or IP address associated with the password item.
        ///   - protocol: Protocol associated with the internet password item.
        ///   - authenticationType: Authentication scheme associated with the internet password item.
        ///   - port: Internet port number associated with the internet password item.
        ///   - path: Path associated with the internet password keychain item.
        ///   - authentication: Keychain query authentication used for the update operation.
        public static func updateItems(
            newPassword: String,
            forAccount account: String,
            accessGroup: String = defaultAccessGroup,
            securityDomain: String? = nil,
            server: String? = nil,
            protocol: InternetPassword.NetworkProtocol? = nil,
            authenticationType: InternetPassword.AuthenticationType? = nil,
            port: UInt16? = nil,
            path: String? = nil,
            accessControl: AccessControl = .afterFirstUnlockThisDeviceOnly,
            authentication: QueryAuthentication = .default
        ) throws {
            guard let valueData = Crypto.KeyData(copyFrom: newPassword as NSString, encoding: .utf8) else {
                throw Keychain.InternetPasswordError.invalidPassword
            }

            var itemAttributes: Set<Keychain.ItemAttribute> = [
                .account(account), .accessGroup(accessGroup),
            ]
            securityDomain.updateMapped({ .securityDomain($0) }, in: &itemAttributes)
            server.updateMapped({ .server($0) }, in: &itemAttributes)
            `protocol`.updateMapped({ .protocol($0) }, in: &itemAttributes)
            authenticationType.updateMapped({ .authenticationType($0) }, in: &itemAttributes)
            port.updateMapped({ .port($0) }, in: &itemAttributes)
            path.updateMapped({ .path($0) }, in: &itemAttributes)

            let query = Keychain.UpdateItemQuery(
                itemClass: itemClass,
                valueData: valueData,
                attributes: itemAttributes
            )
            .add(authentication)

            try Keychain.updateItem(query: query)
        }

        /// Updates or saves an internet password in the keychain.
        ///
        /// This method is just a convenience method to either save a new non-synchronizable internet password item in the keychain or update the existing one if there's already an item with the specified combination of fields in the access group.
        ///
        /// - Parameters:
        ///   - password: The new password value of the item to be saved or updated.
        ///   - account: The account name for the password.
        ///   - accessGroup: Keychain Access group for which the upsert should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
        ///   - securityDomain: The internet security domain associated with the password item.
        ///   - server: Server domain name or IP address associated with the password item.
        ///   - protocol: Protocol associated with the internet password item.
        ///   - authenticationType: Authentication scheme associated with the internet password item.
        ///   - port: Internet port number associated with the internet password item.
        ///   - path: Path associated with the internet password keychain item.
        ///   - accessControl: Indicates when your application needs access to an item's data.  You should choose the most restrictive option that meets your application's needs to allow the system to protect that item in the best way possible. This parameter is only used for saving the password and not for updating the password.
        ///   - label: A keychain item label that can be displayed to the user by apps that have access to the item. This parameter is only used for saving the password and not for updating the password.
        ///   - authentication: Keychain query authentication.
        ///   This parameter is only used for updating the password and not for saving the password.
        public static func upsert(
            _ password: String,
            forAccount account: String,
            accessGroup: String = defaultAccessGroup,
            securityDomain: String = "",
            server: String = "",
            protocol: InternetPassword.NetworkProtocol? = nil,
            authenticationType: InternetPassword.AuthenticationType? = nil,
            port: UInt16 = 0,
            path: String = "",
            accessControl: AccessControl = .afterFirstUnlockThisDeviceOnly,
            label: String? = nil,
            authentication: QueryAuthentication = .default
        ) throws {
            do {
                try save(
                    password,
                    forAccount: account,
                    accessGroup: accessGroup,
                    securityDomain: securityDomain,
                    server: server,
                    protocol: `protocol`,
                    authenticationType: authenticationType,
                    port: port,
                    path: path,
                    accessControl: accessControl,
                    label: label
                )
            } catch let KeychainError.itemSavingFailed(status) where status == errSecDuplicateItem {
                try updateItems(
                    newPassword: password,
                    forAccount: account,
                    accessGroup: accessGroup,
                    securityDomain: securityDomain,
                    server: server,
                    protocol: `protocol`,
                    authenticationType: authenticationType,
                    port: port,
                    path: path,
                    authentication: authentication
                )
            } catch {
                throw error
            }
        }

        /// Deletes internet password items in the keychain.
        ///
        /// Searches and deletes non-synchronizable internet password items in the keychain of the access group identified by a combination of the `account`, `security domain`, `server`, `protocol`, `authentication type`, `port` and `path` fields.
        ///
        /// - Warning: This method may delete one or more keychain items depending on the combination of specified fields.
        /// If only a single entry is to be deleted, you must ensure that the combination of fields uniquely identifies an entry.
        ///
        /// - Parameters:
        ///   - account: Specifies the account name for this password.
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
        public static func deleteItems(
            forAccount account: String,
            accessGroup: String = defaultAccessGroup,
            securityDomain: String? = nil,
            server: String? = nil,
            protocol: InternetPassword.NetworkProtocol? = nil,
            authenticationType: InternetPassword.AuthenticationType? = nil,
            port: UInt16? = nil,
            path: String? = nil
        ) throws -> Bool {
            var itemAttributes: Set<Keychain.ItemAttribute> = [
                .account(account), .accessGroup(accessGroup),
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
}

public extension Keychain.InternetPassword {
    /// Asynchronously queries internet password items in an access group.
    ///
    /// This method queries Internet password entries in the keychain, including synchronizable entries, and returns them as an array of  ``Item`` items.
    ///
    /// - Parameters:
    ///   - account: Specifies the account value with which to restrict the query.
    ///   - service: Specifies the service value with which to restrict the query.
    ///   - server: Specifies the server value with which to restrict the query.
    ///   - protocol: Specifies the protocol value with which to restrict the query.
    ///   - authenticationType: Specifies the authenticationType value with which to restrict the query.
    ///   - port: Specifies the port value with which to restrict the query.
    ///   - path: Specifies the path value with which to restrict the query.
    ///   - accessGroup: Keychain Access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - authentication: Keychain query authentication.
    ///
    /// - Returns: A list of  internet password items of type ``Item``, or `nil` if no item was found.
    static func queryItems(
        forAccount account: String? = nil,
        securityDomain: String? = nil,
        server: String? = nil,
        protocol: Keychain.InternetPassword.NetworkProtocol? = nil,
        authenticationType: Keychain.InternetPassword.AuthenticationType? = nil,
        port: UInt16? = nil,
        path: String? = nil,
        accessGroup: String = Keychain.defaultAccessGroup,
        authentication: Keychain.QueryAuthentication = .default
    ) async throws -> [Item]? {
        try await withCheckedThrowingContinuation { continuation in
            queryItems(
                forAccount: account,
                securityDomain: securityDomain,
                server: server,
                protocol: `protocol`,
                authenticationType: authenticationType,
                port: port,
                path: path,
                accessGroup: accessGroup,
                authentication: authentication
            ) {
                continuation.resume(with: $0)
            }
        }
    }

    /// Asynchronously searches the keychain for a single internet password entry.
    ///
    /// Searches the keychain for a single non-synchronizable internet password item of the access group identified by a unqiue combination of the `account`, `security domain`, `server`, `protocol`, `authentication type`, `port` and `path` fields.
    ///
    /// - Parameters:
    ///   - account: Specifies the account name for this password.
    ///   - accessGroup: Keychain Access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - securityDomain: The internet security domain associated with the password item.
    ///   - server: Server domain name or IP address associated with the password item.
    ///   - protocol: Protocol associated with the internet password item.
    ///   - authenticationType: Authentication scheme associated with the internet password item.
    ///   - port: Internet port number associated with the internet password item.
    ///   - path: Path associated with the internet password keychain item.
    ///   - authentication: Keychain query authentication used for the search operation.
    ///
    /// - Throws: ``KeychainError/ambiguousQueryResult`` if the query returns more than one item.
    /// - Returns: The password for the specified account and service, or `nil` if no item was found.
    static func queryOne(
        forAccount account: String,
        accessGroup: String = Keychain.defaultAccessGroup,
        securityDomain: String? = nil,
        server: String? = nil,
        protocol: NetworkProtocol? = nil,
        authenticationType: AuthenticationType? = nil,
        port: UInt16? = nil,
        path: String? = nil,
        authentication: Keychain.QueryAuthentication = .default
    ) async throws -> String? {
        try await withCheckedThrowingContinuation { continuation in
            queryOne(
                forAccount: account,
                accessGroup: accessGroup,
                securityDomain: securityDomain,
                server: server,
                protocol: `protocol`,
                authenticationType: authenticationType,
                port: port,
                path: path,
                authentication: authentication
            ) {
                continuation.resume(with: $0)
            }
        }
    }
}

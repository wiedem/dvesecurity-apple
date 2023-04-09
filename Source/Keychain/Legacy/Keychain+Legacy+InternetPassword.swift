// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

#if os(macOS)
extension Keychain.Legacy {
    /// An error that occurs during legacy keychain operations with a internet password.
    public enum InternetPasswordError: Error {
        /// An invalid query item limit was specificed.
        case invalidQueryItemLimit
    }

    /// A container for internet password items.
    open class InternetPassword {
        /// Queries internet password items in a file based keychain.
        ///
        /// Fetches a number of internet password entries from a file-based keychain up to a specified limit.
        ///
        /// - Note: Querying keychain entries may result in multiple user prompts for authentication, depending on the ACLs. Therefore, a limit must be specified for the query, which should be chosen wisely to avoid triggering a large number of authentication prompts.
        ///
        /// - Parameters:
        ///   - account: Specifies the account value with which to restrict the query.
        ///   - service: Specifies the service value with which to restrict the query.
        ///   - server: Specifies the server value with which to restrict the query.
        ///   - protocol: Specifies the protocol value with which to restrict the query.
        ///   - authenticationType: Specifies the authenticationType value with which to restrict the query.
        ///   - port: Specifies the port value with which to restrict the query.
        ///   - path: Specifies the path value with which to restrict the query.
        ///   - limit: The maximum number of elements to be retrieved.
        ///   - keychain: The keychain on which to perform the operation or `nil` if the default keychain should be used.
        ///
        /// - Throws: ``Keychain/Legacy/InternetPasswordError/invalidQueryItemLimit`` if the specified limit is invalid.
        /// - Returns: A list of  internet password items of type ``Item``, or `nil` if no item was found.
        open class func queryItems(
            account: String? = nil,
            securityDomain: String? = nil,
            server: String? = nil,
            protocol: Keychain.InternetPassword.NetworkProtocol? = nil,
            authenticationType: Keychain.InternetPassword.AuthenticationType? = nil,
            port: UInt16? = nil,
            path: String? = nil,
            limit: UInt,
            inKeychain keychain: SecKeychain? = nil
        ) throws -> [Item]? {
            guard limit > 0 else {
                throw InternetPasswordError.invalidQueryItemLimit
            }
            var itemAttributes: Set<Keychain.ItemAttribute> = []
            account.updateMapped({ .account($0) }, in: &itemAttributes)
            securityDomain.updateMapped({ .securityDomain($0) }, in: &itemAttributes)
            server.updateMapped({ .server($0) }, in: &itemAttributes)
            `protocol`.updateMapped({ .protocol($0) }, in: &itemAttributes)
            authenticationType.updateMapped({ .authenticationType($0) }, in: &itemAttributes)
            port.updateMapped({ .port($0) }, in: &itemAttributes)
            path.updateMapped({ .path($0) }, in: &itemAttributes)

            let query = Keychain.Legacy.FetchItemsQuery(
                itemClass: itemClass,
                returnType: [.data, .attributes],
                attributes: itemAttributes,
                keychain: keychain
            )
            .setLimit(limit)

            return try Keychain.queryItems(query: query, transform: Keychain.attributesTransform)
        }

        /// Searches a file based keychain for a single internet password entry.
        ///
        /// Searches the keychain for a single non-synchronizable internet password item of the access group identified by a unqiue combination of the `account`, `security domain`, `server`, `protocol`, `authentication type`, `port` and `path` fields.
        ///
        /// Since all fields except the `account` are optional, you must ensure that the specified combination of fields identifies a unique entry.
        ///
        /// Use the ``queryItems(account:securityDomain:server:protocol:authenticationType:port:path:limit:inKeychain:)``  method if you want to use a query which may return multiple items.
        ///
        /// - Parameters:
        ///   - account: Specifies the account name for this password.
        ///   - securityDomain: The internet security domain associated with the password item.
        ///   - server: Server domain name or IP address associated with the password item.
        ///   - protocol: Protocol associated with the internet password item.
        ///   - authenticationType: Authentication scheme associated with the internet password item.
        ///   - port: Internet port number associated with the internet password item.
        ///   - path: Path associated with the internet password keychain item.
        ///   - keychain: The keychain on which to perform the operation or `nil` if the default keychain should be used.
        ///
        /// - Throws: ``KeychainError/ambiguousQueryResult`` if the query returns more than one item.
        /// - Returns: The password for the specified account, or `nil` if no item was found.
        open class func queryOne(
            forAccount account: String,
            securityDomain: String? = nil,
            server: String? = nil,
            protocol: Keychain.InternetPassword.NetworkProtocol? = nil,
            authenticationType: Keychain.InternetPassword.AuthenticationType? = nil,
            port: UInt16? = nil,
            path: String? = nil,
            inKeychain keychain: SecKeychain? = nil
        ) throws -> String? {
            var itemAttributes: Set<Keychain.ItemAttribute> = [.account(account)]

            securityDomain.updateMapped({ .securityDomain($0) }, in: &itemAttributes)
            server.updateMapped({ .server($0) }, in: &itemAttributes)
            `protocol`.updateMapped({ .protocol($0) }, in: &itemAttributes)
            authenticationType.updateMapped({ .authenticationType($0) }, in: &itemAttributes)
            port.updateMapped({ .port($0) }, in: &itemAttributes)
            path.updateMapped({ .path($0) }, in: &itemAttributes)

            let query = Keychain.Legacy.FetchItemsQuery(
                itemClass: itemClass,
                returnType: .data,
                attributes: itemAttributes,
                keychain: keychain
            )
            return try Keychain.queryOneItem(query: query, transform: Keychain.dataResultItemsToString)
        }

        /// Adds an internet password to a file based keychain.
        ///
        /// Saves a internet password in a file based keychain for a specific account and with the given fields.
        ///
        /// An entry for the specified account must not yet exist in the keychain, otherwise the error ``KeychainError/itemSavingFailed(status:)``  will be thrown with a status code value `errSecDuplicateItem`.
        ///
        /// - Note: Internet passwords are uniquely identified in the keychain by a combination of the `account`, `security domain`, `server`, `protocol`, `authentication type`, `port` and `path` fields.
        /// I.e. these fields are primary keys and affect how you can uniquely identify and query an item.
        ///
        /// - Parameters:
        ///   - password: The password to save.
        ///   - account: The unique account name for the password item.
        ///   - securityDomain: The internet security domain associated with the password item.
        ///   - server: Server domain name or IP address associated with the password item.
        ///   - protocol: Protocol associated with the internet password item.
        ///   - authenticationType: Authentication scheme associated with the internet password item.
        ///   - port: Internet port number associated with the internet password item.
        ///   - path: Path associated with the internet password keychain item.
        ///   - label: Specifies the user-visible label for this item. This value is visible to the user in the macOS Keychain Access app and should therefore be chosen so that the user can identify the item.
        ///   - keychain: The keychain on which to perform the operation or `nil` if the default keychain should be used.
        ///   - access: Access instance indicating access control list settings for the password. See [Access Control Lists](https://developer.apple.com/documentation/security/keychain_services/access_control_lists).
        open class func save(
            _ password: String,
            forAccount account: String,
            securityDomain: String? = nil,
            server: String? = "",
            protocol: Keychain.InternetPassword.NetworkProtocol? = nil,
            authenticationType: Keychain.InternetPassword.AuthenticationType? = nil,
            port: UInt16? = nil,
            path: String? = nil,
            label: String,
            inKeychain keychain: SecKeychain? = nil,
            access: SecAccess? = nil
        ) throws {
            guard let data = password.data(using: .utf8) else {
                throw Keychain.InternetPasswordError.invalidPassword
            }

            var itemAttributes: Set<Keychain.ItemAttribute> = [.account(account), .label(label)]

            securityDomain.updateMapped({ .securityDomain($0) }, in: &itemAttributes)
            server.updateMapped({ .server($0) }, in: &itemAttributes)
            `protocol`.updateMapped({ .protocol($0) }, in: &itemAttributes)
            authenticationType.updateMapped({ .authenticationType($0) }, in: &itemAttributes)
            port.updateMapped({ .port($0) }, in: &itemAttributes)
            path.updateMapped({ .path($0) }, in: &itemAttributes)

            let query = Keychain.Legacy.AddItemQuery(
                itemClass: itemClass,
                valueData: data,
                attributes: itemAttributes,
                keychain: keychain,
                access: access
            )
            try Keychain.saveItem(query: query)
        }

        /// Deletes internet password items in a file based keychain.
        ///
        /// Searches and deletes non-synchronizable internet password items in a file based keychain identified by a combination of the `account`, `security domain`, `server`, `protocol`, `authentication type`, `port` and `path` fields.
        ///
        /// - Warning: This method may delete one or more keychain items depending on the combination of specified fields.
        /// If only a single entry is to be deleted, you must ensure that the combination of fields uniquely identifies an entry.
        ///
        /// - Parameters:
        ///   - account: Specifies the account name for this password.
        ///   - securityDomain: The internet security domain associated with the password item.
        ///   - server: Server domain name or IP address associated with the password item.
        ///   - protocol: Protocol associated with the internet password item.
        ///   - authenticationType: Authentication scheme associated with the internet password item.
        ///   - port: Internet port number associated with the internet password item.
        ///   - path: Path associated with the internet password keychain item.
        ///   - keychain: The keychain on which to perform the operation or `nil` if the default keychain should be used.
        ///
        /// - Returns: `true` if at least one item in the keychain was deleted, `false` otherwise.
        @discardableResult
        open class func deleteItems(
            forAccount account: String,
            securityDomain: String? = nil,
            server: String? = nil,
            protocol: Keychain.InternetPassword.NetworkProtocol? = nil,
            authenticationType: Keychain.InternetPassword.AuthenticationType? = nil,
            port: UInt16? = nil,
            path: String? = nil,
            inKeychain keychain: SecKeychain? = nil
        ) throws -> Bool {
            var itemAttributes: Set<Keychain.ItemAttribute> = [.account(account)]

            securityDomain.updateMapped({ .securityDomain($0) }, in: &itemAttributes)
            server.updateMapped({ .server($0) }, in: &itemAttributes)
            `protocol`.updateMapped({ .protocol($0) }, in: &itemAttributes)
            authenticationType.updateMapped({ .authenticationType($0) }, in: &itemAttributes)
            port.updateMapped({ .port($0) }, in: &itemAttributes)
            path.updateMapped({ .path($0) }, in: &itemAttributes)

            let query = Keychain.Legacy.DeleteItemsQuery(
                itemClass: itemClass,
                attributes: itemAttributes,
                keychain: keychain
            )
            return try Keychain.deleteItems(query: query)
        }
    }
}

public extension Keychain.Legacy.InternetPassword {
    typealias Item = Keychain.InternetPassword.Item
}
#endif

// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

#if os(macOS)
extension Keychain.Legacy {
    /// An error that occurs during legacy keychain operations with a generic password.
    public enum GenericPasswordError: Error {
        /// An invalid query item limit was specificed.
        case invalidQueryItemLimit
    }

    /// A container for generic password items.
    open class GenericPassword {
        /// Searches a file based keychain for a generic password.
        ///
        /// Searches a file based keychain for a generic non-synchronizable password and returns the entry as a UTF-8 encoded `String` value.
        ///
        /// Returns a ``KeychainError/resultError`` if the value of the entry cannot be decoded to a String.
        ///
        /// - Parameters:
        ///   - account: Specifies the account name for the password.
        ///   - service: Specifies the service associated with the password.
        ///   - keychain: The keychain on which to perform the operation or `nil` if the default keychain should be used.
        ///
        /// - Throws: ``KeychainError/resultError`` if the value of the entry cannot be decoded to a String.
        /// - Returns: The password for the specified account and service, or `nil` if no item was found.
        open class func query(
            forAccount account: String,
            service: String,
            inKeychain keychain: SecKeychain? = nil
        ) throws -> String? {
            let query = Keychain.Legacy.FetchItemsQuery(
                itemClass: itemClass,
                returnType: .data,
                attributes: [.account(account), .service(service)],
                keychain: keychain
            )
            return try Keychain.queryOneItem(query: query, transform: Keychain.dataResultItemsToString)
        }

        /// Queries generic password items in a file based keychain.
        ///
        /// Fetches a number of generic password entries from a file based keychain up to a specified limit.
        ///
        /// - Note: Querying keychain entries may result in multiple user prompts for authentication, depending on the ACLs. Therefore, a limit must be specified for the query, which should be chosen wisely to avoid triggering a large number of authentication prompts.
        ///
        /// - Parameters:
        ///   - account: Specifies the account value with which to restrict the query.
        ///   - service: Specifies the service value with which to restrict the query.
        ///   - limit: The maximum number of elements to be retrieved.
        ///   - keychain: The keychain on which to perform the operation or `nil` if the default keychain should be used.
        ///
        /// - Throws: ``Keychain/Legacy/GenericPasswordError/invalidQueryItemLimit`` if the specified limit is invalid.
        /// - Returns: A list of  generic password items of type ``Item``, or `nil` if no item was found.
        open class func queryItems(
            account: String? = nil,
            service: String? = nil,
            limit: UInt,
            inKeychain keychain: SecKeychain? = nil
        ) throws -> [Item]? {
            guard limit > 0 else {
                throw GenericPasswordError.invalidQueryItemLimit
            }
            var itemAttributes: Set<Keychain.ItemAttribute> = []
            account.updateMapped({ .account($0) }, in: &itemAttributes)
            service.updateMapped({ .service($0) }, in: &itemAttributes)

            let query = Keychain.Legacy.FetchItemsQuery(
                itemClass: itemClass,
                returnType: [.data, .attributes],
                attributes: itemAttributes,
                keychain: keychain
            )
            .setLimit(limit)

            return try Keychain.queryItems(query: query, transform: Keychain.attributesTransform)
        }

        /// Adds a generic password to a file based keychain.
        ///
        /// Saves a generic password to a file based keychain for a specific account and service with a specific access control. The password is stored as the UTF-8 encoded data representation of the string.
        ///
        /// An entry for the specified account and service must not yet exist in the keychain, otherwise the error ``KeychainError/itemSavingFailed(status:)``  will be thrown with a status code value `errSecDuplicateItem`.
        ///
        /// - Parameters:
        ///   - password: Specifies the password to save.
        ///   - account: Specifies the account name for this password.
        ///   - service: Specifies the service associated with this password.
        ///   - keychain: The keychain on which to perform the operation or `nil` if the default keychain should be used.
        ///   - label: Specifies the user-visible label for this item. This value is visible to the user in the macOS Keychain Access app and should therefore be chosen so that the user can identify the item.
        ///   - access: Access instance indicating access control list settings for the password. See [Access Control Lists](https://developer.apple.com/documentation/security/keychain_services/access_control_lists).
        open class func save(
            _ password: String,
            forAccount account: String,
            service: String,
            label: String,
            inKeychain keychain: SecKeychain? = nil,
            access: SecAccess? = nil
        ) throws {
            guard let data = password.data(using: .utf8) else {
                throw Keychain.GenericPasswordError.invalidPassword
            }

            let query = Keychain.Legacy.AddItemQuery(
                itemClass: itemClass,
                valueData: data,
                attributes: [.account(account), .service(service), .label(label)],
                keychain: keychain,
                access: access
            )
            try Keychain.saveItem(query: query)
        }

        /// Deletes a generic password in a file based keychain.
        ///
        /// Deletes a generic password in a file based keychain for a specific account and service.
        ///
        /// - Note: No error is thrown if no element with the specified parameters can be found. Instead, the method returns `false` as a return value.
        ///
        /// - Parameters:
        ///   - account: Specifies the account name for the password.
        ///   - service: Specifies the service associated with the password
        ///   - keychain: The keychain on which to perform the operation or `nil` if the default keychain should be used.
        ///
        /// - Returns: `true` if an item matching the parameters was deleted, `false` otherwise.
        @discardableResult
        open class func delete(
            forAccount account: String,
            service: String,
            inKeychain keychain: SecKeychain? = nil
        ) throws -> Bool {
            let query = Keychain.Legacy.DeleteItemsQuery(
                itemClass: itemClass,
                attributes: [.account(account), .service(service)],
                keychain: keychain
            )
            return try Keychain.deleteItems(query: query)
        }
    }
}
#endif

// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

extension Keychain.GenericPassword {
    /// Searches the keychain for a key saved as a synchronizable generic password.
    ///
    /// - Parameters:
    ///   - account: Specifies the account name for the password.
    ///   - service: Specifies the service associated with the password.
    ///   - accessGroup: Keychain Access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - completion: The completion handler called after the query is completed. This handler is executed on a background thread.
    public class func querySynchronizableKey<K>(
        forAccount account: String,
        service: String,
        accessGroup: String = Keychain.defaultAccessGroup,
        completion: @escaping (Result<K?, Error>) -> Void
    ) where K: RawKeyConvertible {
        let itemAttributes: Set<Keychain.ItemAttribute> = [
            .account(account), .service(service), .accessGroup(accessGroup), .synchronizable(),
        ]

        let query = Keychain.FetchItemsQuery(itemClass: itemClass, returnType: .data, attributes: itemAttributes)
        Keychain.queryOneItem(query: query, transform: Keychain.dataResultItemsToKeys, completion: completion)
    }

    /// Saves a key as a synchronizable generic password item in the keychain.
    ///
    /// Saves a non-synchronizable key conforming to the ``RawKeyConvertible`` protocol for the specified account and service in the keychain.
    ///
    /// This method can be used to save arbitrary data of a cryptographic key in the keychain.
    /// It should however not be used for key types directly supported by the keychain like certain symmetric keys, RSA keys and ECC keys.
    ///
    /// - Parameters:
    ///   - key: The key for which the data should be saved.
    ///   - account: Specifies the account name for the password.
    ///   - service: Specifies the service associated with the password.
    ///   - accessGroup: Keychain Access group for which the save should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - accessibility: Indicates when your application needs access to an item's data. You should choose the most restrictive option that meets your application's needs to allow the system to protect that item in the best way possible.
    ///   - label: A keychain item label that can be displayed to the user by apps that have access to the item.
    ///   allow the system to protect that item in the best way possible.
    public class func saveSynchronizableKey(
        _ key: some RawKeyConvertible,
        forAccount account: String,
        service: String,
        accessGroup: String = Keychain.defaultAccessGroup,
        accessibility: Keychain.SynchronizableItemAccessibility = .afterFirstUnlock,
        label: String? = nil
    ) throws {
        var itemAttributes: Set<Keychain.ItemAttribute> = [
            .account(account),
            .service(service),
            .accessGroup(accessGroup),
            .synchronizable(accessibility: accessibility),
        ]
        label.updateMapped({ .label($0) }, in: &itemAttributes)

        let query = Keychain.AddItemQuery(itemClass: itemClass, valueData: key.rawKeyRepresentation, attributes: itemAttributes)
        try Keychain.saveItem(query: query)
    }
}

@available(iOS 13.0, *)
extension Keychain.GenericPassword {
    /// Searches the keychain for a key saved as a synchronizable generic password.
    ///
    /// - Parameters:
    ///   - account: Specifies the account name for the password.
    ///   - service: Specifies the service associated with the password.
    ///   - accessGroup: Keychain Access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///
    /// - Returns: The key for the specified account and service, or `nil` if no item was found.
    public class func querySynchronizableKey<K>(
        forAccount account: String,
        service: String,
        accessGroup: String = Keychain.defaultAccessGroup
    ) throws -> K? where K: RawKeyConvertible {
        let itemAttributes: Set<Keychain.ItemAttribute> = [
            .account(account), .service(service), .accessGroup(accessGroup), .synchronizable(),
        ]

        let query = Keychain.FetchItemsQuery(itemClass: itemClass, returnType: .data, attributes: itemAttributes)
        return try Keychain.queryOneItem(query: query, transform: Keychain.dataResultItemsToKeys)
    }
}

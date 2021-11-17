// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
#if canImport(Combine)
import Combine
import LocalAuthentication

@available(iOS 13, *)
extension Keychain.InternetPassword {
    /// Returns a publisher which searches the keychain for a unique internet password entry.
    ///
    /// The publisher searches the keychain for a single non-synchronizable internet password item of the access group identified by a unqiue combination of the `account`, `security domain`, `server`, `protocol`, `authentication type`, `port` and `path` fields.
    ///
    /// Since all fields except the `account` are optional, you must ensure that the specified combination of fields identifies a unique entry.
    /// If the query returns more than one item the publisher will fail with a ``KeychainError/ambiguousQueryResult`` error.
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
    open class func queryOnePublisher(
        forAccount account: String,
        accessGroup: String = Keychain.defaultAccessGroup,
        securityDomain: String? = nil,
        server: String? = nil,
        protocol: Keychain.InternetPassword.NetworkProtocol? = nil,
        authenticationType: Keychain.InternetPassword.AuthenticationType? = nil,
        port: UInt16? = nil,
        path: String? = nil,
        authentication: Keychain.QueryAuthentication = .default
    ) -> AnyPublisher<String?, Error> {
        Future { promise in
            queryOne(forAccount: account,
                     accessGroup: accessGroup,
                     securityDomain: securityDomain,
                     server: server,
                     protocol: `protocol`,
                     authenticationType: authenticationType,
                     port: port,
                     path: path,
                     authentication: authentication) {
                promise($0)
            }
        }
        .eraseToAnyPublisher()
    }

    /// Returns a publisher which searches the keychain for a unique internet password entry that is synced via iCloud..
    ///
    /// The publisher searches the keychain for a single synchronizable internet password item of the access group identified by a unqiue combination of the `account`, `security domain`, `server`, `protocol`, `authentication type`, `port` and `path` fields.
    ///
    /// Since all fields except the `account` are optional, you must ensure that the specified combination of fields identifies a unique entry.
    /// If the query returns more than one item the publisher will fail with a ``KeychainError/ambiguousQueryResult`` error.
    ///
    /// - Parameters:
    ///   - account: Specifies the account name for this password.
    ///   - accessGroup: Keychain access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - securityDomain: The internet security domain associated with the password item.
    ///   - server: Server domain name or IP address associated with the password item.
    ///   - protocol: Protocol associated with the internet password item.
    ///   - authenticationType: Authentication scheme associated with the internet password item.
    ///   - port: Internet port number associated with the internet password item.
    ///   - path: Path associated with the internet password keychain item.
    open class func queryOneSynchronizablePublisher(
        forAccount account: String,
        accessGroup: String = Keychain.defaultAccessGroup,
        securityDomain: String? = nil,
        server: String? = nil,
        protocol: Keychain.InternetPassword.NetworkProtocol? = nil,
        authenticationType: Keychain.InternetPassword.AuthenticationType? = nil,
        port: UInt16? = nil,
        path: String? = nil
    ) -> AnyPublisher<String?, Error> {
        Future { promise in
            queryOneSynchronizable(forAccount: account,
                                   accessGroup: accessGroup,
                                   securityDomain: securityDomain,
                                   server: server,
                                   protocol: `protocol`,
                                   authenticationType: authenticationType,
                                   port: port,
                                   path: path) {
                promise($0)
            }
        }
        .eraseToAnyPublisher()
    }

    /// Returns a publisher that adds an internet password to the keychain.
    ///
    /// The publisher saves a non-synchronizable internet password in the keychain for a specific account and with the given fields.
    ///
    /// An entry for the specified account must not yet exist in the keychain, otherwise the publisher will fail with a ``KeychainError/itemSavingFailed(status:)``  error with a status code value `errSecDuplicateItem`.
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
    open class func savePublisher(
        for password: String,
        account: String,
        accessGroup: String = Keychain.defaultAccessGroup,
        securityDomain: String = "",
        server: String = "",
        protocol: Keychain.InternetPassword.NetworkProtocol? = nil,
        authenticationType: Keychain.InternetPassword.AuthenticationType? = nil,
        port: UInt16 = 0,
        path: String = "",
        accessControl: Keychain.AccessControl = .afterFirstUnlockThisDeviceOnly,
        authenticationContext: LAContext? = nil
    ) -> AnyPublisher<Keychain.InternetPassword.Type, Error> {
        Future { promise in
            do {
                try save(password,
                         forAccount: account,
                         accessGroup: accessGroup,
                         securityDomain: securityDomain,
                         server: server,
                         protocol: `protocol`,
                         authenticationType: authenticationType,
                         port: port,
                         path: path,
                         accessControl: accessControl,
                         authenticationContext: authenticationContext)
                promise(.success(Self.self))
            } catch {
                promise(.failure(error))
            }
        }
        .eraseToAnyPublisher()
    }

    /// Returns a publisher that adds an internet password to the keychain that is synced via iCloud.
    ///
    /// The publisher saves a synchronizable internet password in the keychain for a specific account and with the given fields.
    ///
    /// An entry for the specified account must not yet exist in the keychain, otherwise the publisher will fail with a ``KeychainError/itemSavingFailed(status:)``  error with a status code value `errSecDuplicateItem`.
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
    ///   - accessibility: Indicates when your application needs access to an item's data.  You should choose the most restrictive option that meets your application's needs to
    ///   allow the system to protect that item in the best way possible.
    open class func saveSynchronizablePublisher(
        for password: String,
        account: String,
        accessGroup: String = Keychain.defaultAccessGroup,
        securityDomain: String? = nil,
        server: String? = nil,
        protocol: Keychain.InternetPassword.NetworkProtocol? = nil,
        authenticationType: Keychain.InternetPassword.AuthenticationType? = nil,
        port: UInt16? = nil,
        path: String? = nil,
        accessibility: Keychain.SynchronizableItemAccessibility = .afterFirstUnlock
    ) -> AnyPublisher<Keychain.InternetPassword.Type, Error> {
        Future { promise in
            do {
                try saveSynchronizable(
                    password,
                    forAccount: account,
                    accessGroup: accessGroup,
                    securityDomain: securityDomain,
                    server: server,
                    protocol: `protocol`,
                    authenticationType: authenticationType,
                    port: port,
                    path: path,
                    accessibility: accessibility
                )
                promise(.success(Self.self))
            } catch {
                promise(.failure(error))
            }
        }
        .eraseToAnyPublisher()
    }
}
#endif

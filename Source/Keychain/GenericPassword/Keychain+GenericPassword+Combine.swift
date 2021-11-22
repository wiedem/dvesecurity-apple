// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
#if canImport(Combine)
import Combine
import LocalAuthentication

@available(iOS 13.0, *)
extension Keychain.GenericPassword {
    /// Returns a publisher that searches the keychain for a generic password.
    ///
    /// The entry in the keychain is uniquely identified by the account name and the associated service.
    ///
    /// - Parameters:
    ///   - account: Specifies the account name for this password.
    ///   - service: Specifies the service associated with this password.
    ///   - accessGroup: Keychain access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - authentication: Keychain query authentication.
    open class func queryPublisher(
        forAccount account: String,
        service: String,
        accessGroup: String = Keychain.defaultAccessGroup,
        authentication: Keychain.QueryAuthentication = .default
    ) -> AnyPublisher<String?, Error> {
        Future { promise in
            query(forAccount: account, service: service, accessGroup: accessGroup, authentication: authentication) { result in
                promise(result)
            }
        }
        .eraseToAnyPublisher()
    }

    /// Returns a publisher that searches the keychain for a synchronizable generic password.
    ///
    /// The entry in the keychain is uniquely identified by the account name and the associated service.
    ///
    /// - Parameters:
    ///   - account: Specifies the account name for this password.
    ///   - service: Specifies the service associated with this password.
    ///   - accessGroup: Keychain access group for which the search should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    open class func querySynchronizablePublisher(
        forAccount account: String,
        service: String,
        accessGroup: String = Keychain.defaultAccessGroup
    ) -> AnyPublisher<String?, Error> {
        Future { promise in
            querySynchronizable(forAccount: account, service: service, accessGroup: accessGroup) { result in
                promise(result)
            }
        }
        .eraseToAnyPublisher()
    }

    /// Returns a publisher that saves a generic password to the keychain for a specific account and service with a specific access control.
    ///
    /// The entry in the keychain is uniquely identified by the account name and the associated service.
    ///
    /// - Parameters:
    ///   - password: Specifies the password to save.
    ///   - account: Specifies the account name for this password.
    ///   - service: Specifies the service associated with this password.
    ///   - accessGroup: Keychain Access group for which the save should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - accessControl: Indicates when your application needs access to an item's data. You should choose the most restrictive option that meets your application's needs to
    ///   - authenticationContext: A local authentication context to use.
    open class func savePublisher(
        for password: String,
        account: String,
        service: String,
        accessGroup: String = Keychain.defaultAccessGroup,
        accessControl: Keychain.AccessControl = .afterFirstUnlockThisDeviceOnly,
        authenticationContext: LAContext? = nil
    ) -> AnyPublisher<Keychain.GenericPassword.Type, Error> {
        Future { promise in
            do {
                try save(
                    password,
                    forAccount: account,
                    service: service,
                    accessGroup: accessGroup,
                    accessControl: accessControl,
                    authenticationContext: authenticationContext
                )
                promise(.success(Self.self))
            } catch {
                promise(.failure(error))
            }
        }
        .eraseToAnyPublisher()
    }

    /// Returns a publisher that saves a synchronizable generic password to the keychain for a specific account and service with a specific accessibility.
    ///
    /// The entry in the keychain is uniquely identified by the account name and the associated service.
    ///
    /// - Parameters:
    ///   - password: Specifies the password to save.
    ///   - account: Specifies the account name for this password.
    ///   - service: Specifies the service associated with this password.
    ///   - accessGroup: Keychain Access group for which the save should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - accessibility: Indicates when your application needs access to an item's data. You should choose the most restrictive option that meets your application's needs to
    open class func saveSynchronizablePublisher(
        for password: String,
        account: String,
        service: String,
        accessGroup: String = Keychain.defaultAccessGroup,
        accessibility: Keychain.SynchronizableItemAccessibility = .afterFirstUnlock
    ) -> AnyPublisher<Keychain.GenericPassword.Type, Error> {
        Future { promise in
            do {
                try saveSynchronizable(
                    password,
                    forAccount: account,
                    service: service,
                    accessGroup: accessGroup
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

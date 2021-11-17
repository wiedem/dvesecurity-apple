// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

public extension Crypto.ECC {
    enum SecureEnclaveKeyError: Error {
        case unsupportedCurve
    }

    /// A Elliptic Curve Cryptography private key saved in the Secure Enclave.
    struct SecureEnclaveKey: ECCSecureEnclaveKey, CustomDebugStringConvertible {
        public var secKey: SecKey

        public init() throws {
            secKey = try Crypto.Asymmetric.createSecureEnclavePrivateKey()
        }
    }
}

extension Crypto.ECC.SecureEnclaveKey: SecKeyConvertible {
    /// Creates a new Secure Enclave ECC private key from a given `SecKey`.
    ///
    /// - Parameter secKey: The `SecKey` from which the Secure Enclave private key should be created.
    ///
    /// - Throws: ``Crypto/KeyError/invalidSecKey`` if the SecKey is no valid Secure Enclave private key.
    public init(secKey: SecKey) throws {
        let (secKeyClass, secKeyAttributes) = Self.secKeyAttributes(for: secKey)
        guard let keyClass = secKeyClass, keyClass == Self.secKeyClass else {
            throw Crypto.KeyError.invalidSecKey
        }
        guard secKeyAttributes?.isBackedBySecureEnclave == true else {
            throw Crypto.KeyError.invalidSecKey
        }
        self.secKey = secKey
    }
}

public extension Crypto.ECC.SecureEnclaveKey {
    /// Creates a new ECC private key in the Secure Enclave and adds a reference of it to the keychain.
    ///
    /// Make sure you use an access control with the flag ``Keychain/AccessControlFlag/privateKeyUsage``  set when creating a Secure Enclave private key.
    ///
    /// This flag indicates that the private key should be available for use in signing and verification operations inside the Secure Enclave. Without the flag, key generation still succeeds, but signing operations that attempt to use it fail.
    ///
    /// Also make sure the access control uses an item accessibility which limits it to the current device since Secure Enclave keys cannot be transferred to other systems.
    ///
    /// - Parameters:
    ///   - keychainTag: The private keychain tag data used for the key.
    ///   - accessGroup: Keychain Access group for which the save should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - accessControl: Access control value of the key. Sets the conditions under which an app can access the item. The default value for this parameter is an access control value with the protection parameter ``Keychain/AccessControl/whenUnlockedThisDeviceOnly`` and the access control flags set to ``Keychain/AccessControlFlag/privateKeyUsage``.
    init(
        inKeychainWithTag keychainTag: String,
        accessGroup: String = Keychain.defaultAccessGroup,
        accessControl: Keychain.AccessControl = .defaultSecureEnclaveAccessControl
    ) throws {
        let secKey = try Crypto.Asymmetric.createSecureEnclavePrivateKeyInKeychain(tag: keychainTag, accessGroup: accessGroup, accessControl: accessControl)
        try self.init(secKey: secKey)
    }
}

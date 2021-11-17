// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import LocalAuthentication
import Security

public extension Crypto.RSA {
    /// A RSA private key.
    ///
    /// This type internally uses a `SecKey` instance that is compatible with the Data Protection Keychain. Instances of this type can thus be stored in this keychain type using the ``Keychain/saveKey(_:withTag:accessGroup:accessControl:label:authenticationContext:)-3fhlv`` method.
    ///
    /// - Note: Keys of this type don't support legacy macOS file-based keychains.
    struct PrivateKey: RSAPrivateKey {
        public let secKey: SecKey

        /// Creates a new RSA private key.
        ///
        /// The key size of the key has to be a multiple of 8. Valid value ranges for the key size are platform and OS version specific but are usually between 512 and 8192 bits (e.g. see `kSecRSAMax` on macOS platforms).
        /// Other key sizes may not be supported and trying to use them may throw an error.
        ///
        /// - Note: You should not use key sizes below 2048 bits since they should be considered cryptographically weak.
        ///
        /// - Parameter bitCount: The number of bits in the RSA key.
        public init(bitCount: Int) throws {
            secKey = try Crypto.Asymmetric.createPrivateKey(keyType: .RSA, keySizeInBits: bitCount)
        }

        /// Returns the generated RSA public key for this private key.
        ///
        /// - Returns: A RSA public key instance of type ``Crypto/RSA/PublicKey``.
        public func publicKey() -> PublicKey {
            expectNoError {
                try PublicKey(privateKey: self)
            }
        }
    }
}

extension Crypto.RSA.PrivateKey: PKCS1Convertible, CustomDebugStringConvertible {}

extension Crypto.RSA.PrivateKey: SecKeyConvertible {
    /// Creates a RSA private key instance from a given `SecKey`.
    ///
    /// - Parameter secKey: The `SecKey` from which the RSA private key should be created.
    ///
    /// - Throws: ``Crypto/KeyError/invalidSecKey`` if the `SecKey` is no valid RSA private key.
    public init(secKey: SecKey) throws {
        let (secKeyClass, _) = Self.secKeyAttributes(for: secKey)
        guard let keyClass = secKeyClass, keyClass == Self.secKeyClass else {
            throw Crypto.KeyError.invalidSecKey
        }
        self.secKey = secKey
    }
}

public extension Crypto.RSA.PrivateKey {
    /// Creates a new RSA private key and adds it to the keychain.
    ///
    /// - Parameters:
    ///   - bitCount: Number of bits for the RSA key.
    ///   - keychainTag: The private keychain tag data used for the key.
    ///   - accessGroup: Keychain Access group for which the save should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - accessControl: Access control value of the key. Sets the conditions under which an app can access the item.
    ///   - authenticationContext: A local authentication context to use.
    init(
        bitCount: Int,
        inKeychainWithTag keychainTag: String,
        accessGroup: String = Keychain.defaultAccessGroup,
        accessControl: Keychain.AccessControl = .afterFirstUnlockThisDeviceOnly,
        authenticationContext: LAContext? = nil
    ) throws {
        let secKey = try Crypto.Asymmetric.createPrivateKeyInKeychain(
            keyType: .RSA,
            keySizeInBits: bitCount,
            tag: keychainTag,
            accessGroup: accessGroup,
            accessControl: accessControl,
            authenticationContext: authenticationContext
        )
        try self.init(secKey: secKey)
    }
}

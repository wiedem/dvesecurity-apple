// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import LocalAuthentication
import Security

public extension Crypto.ECC {
    // swiftlint:disable identifier_name
    /// Elliptic curves used for ECC methods and types.
    enum EllipticCurve {
        case p192
        case p256
        case p384
        case p521
    }

    // swiftlint:enable identifier_name

    /// A Elliptic Curve Cryptography private key.
    ///
    /// This type internally uses a `SecKey` instance that is compatible with the Data Protection Keychain. Instances of this type can thus be stored in this keychain type using the ``Keychain/saveKey(_:withTag:accessGroup:accessControl:label:authenticationContext:)-9x3dp`` method.
    ///
    /// - Note: Keys of this type don't support legacy macOS file-based keychains.
    struct PrivateKey: ECCPrivateKey, X963Convertible, CustomDebugStringConvertible {
        /// The `SecKey` representation of the ECC private key.
        public let secKey: SecKey

        /// Creates a random ECC private key.
        ///
        /// - Parameter curve: The elliptic curve used for the key creation.
        public init(curve: EllipticCurve) {
            secKey = expectNoError {
                try Crypto.Asymmetric.createPrivateKey(keyType: .ellipticCurve, keySizeInBits: curve.secKeySizeInBits)
            }
        }

        /// Returns the generated ECC public key for this private key.
        ///
        /// - Returns: A ECC public key instance of type ``Crypto/ECC/PublicKey``.
        public func publicKey() -> PublicKey {
            expectNoError {
                try PublicKey(privateKey: self)
            }
        }
    }
}

extension Crypto.ECC.PrivateKey: SecKeyConvertible {
    /// Creates a ECC private key instance from a given `SecKey`.
    ///
    /// - Parameter secKey: The `SecKey` from which the ECC private key should be created.
    ///
    /// - Throws: ``Crypto/KeyError/invalidSecKey`` if the `SecKey` is no valid ECC private key.
    public init(secKey: SecKey) throws {
        let (secKeyClass, secKeyAttributes) = Self.secKeyAttributes(for: secKey)
        guard let keyClass = secKeyClass, keyClass == Self.secKeyClass else {
            throw Crypto.KeyError.invalidSecKey
        }
        guard secKeyAttributes?.isBackedBySecureEnclave != true else {
            throw Crypto.KeyError.invalidSecKey
        }
        self.secKey = secKey
    }
}

public extension Crypto.ECC.PrivateKey {
    /// Creates a new ECC private key and adds it to the keychain.
    ///
    /// - Parameters:
    ///   - curve: ECC curve of the key.
    ///   - keychainTag: The private keychain tag data used for the key.
    ///   - accessGroup: Keychain Access group for which the save should be performed. If you don’t explicitly specify a group, the default keychain access group will be used.
    ///   - accessControl: Access control value of the key. Sets the conditions under which an app can access the item.
    ///   - authenticationContext: A local authentication context to use.
    init(
        curve: Crypto.ECC.EllipticCurve,
        inKeychainWithTag keychainTag: String,
        accessGroup: String = Keychain.defaultAccessGroup,
        accessControl: Keychain.AccessControl = .afterFirstUnlockThisDeviceOnly,
        authenticationContext: LAContext? = nil
    ) throws {
        let secKey = try Crypto.Asymmetric.createPrivateKeyInKeychain(
            keyType: .ellipticCurve,
            keySizeInBits: curve.secKeySizeInBits,
            tag: keychainTag,
            accessGroup: accessGroup,
            accessControl: accessControl,
            authenticationContext: authenticationContext
        )
        try self.init(secKey: secKey)
    }
}

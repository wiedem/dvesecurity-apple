// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

/// A type that defines to which key class it corresponds in the Security Framework.
public protocol DefinesSecKeyClass {
    /// The corresponding ``SecKeyClass`` of this type.
    ///
    /// The returned value defines the ``SecKeyClass`` of the type that can be used for [Security Framework](https://developer.apple.com/documentation/security) operations.
    static var secKeyClass: SecKeyClass { get }
}

/// A type that can be converted to a `SecKey` instance.
public protocol ConvertibleToSecKey {
    /// A `SecKey` instance representation of this type.
    var secKey: SecKey { get }
}

/// A type that can be initialized from `SecKey` instances.
public protocol CreateableFromSecKey {
    /// Creates this type from a `SecKey` instance.
    ///
    /// - Parameter secKey: The `SecKey` from which this type should be created.
    init(secKey: SecKey) throws
}

/// A type that can be initialized from `SecKey` instances and converted to a `SecKey` instance.
public protocol SecKeyConvertible: ConvertibleToSecKey & CreateableFromSecKey {}

public extension ConvertibleToSecKey {
    /// Gets the attributes of a given security key.
    ///
    /// - Parameter secKey: The key whose attributes you want.
    ///
    /// - Returns: Returns the key class and key attributes if available.
    static func secKeyAttributes(for secKey: SecKey) -> (SecKeyClass?, SecKeyAttributes?) {
        guard let attributes = SecKeyCopyAttributes(secKey) as? [String: Any] else {
            return (nil, nil)
        }

        let keyClass = SecKeyClass(from: attributes)
        let keyAttributes = SecKeyAttributes(secAttributes: attributes)
        return (keyClass, keyAttributes)
    }

    /// The sec key class and attributes of the instance.
    var secKeyAttributes: (SecKeyClass?, SecKeyAttributes?) {
        Self.secKeyAttributes(for: secKey)
    }

    /// Returns an external representation of the given key suitable for the key's type.
    ///
    /// The operation fails if the key is not exportable, for example if it is bound to a smart card or to the Secure Enclave.
    ///
    /// The method returns data in the PKCS #1 format for an RSA key.
    /// For an elliptic curve public key, the format follows the ANSI X9.63 standard using a byte string of 04 || X || Y.
    /// For an elliptic curve private key, the output is formatted as the public key concatenated with the big endian encoding of the secret scalar, or 04 || X || Y || K.
    ///
    /// All of these representations use constant size integers, including leading zeros as needed.
    ///
    /// - Returns: A data object representing the key in a format suitable for the key type.
    func secKeyExternalRepresentation() throws -> Data {
        try secKey.externalRepresentation()
    }
}

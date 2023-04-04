// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

/// A type representing a RSA private key.
public protocol RSAPrivateKey: RSAKey, DefinesSecKeyClass {
    /// Creates a new RSA private key.
    ///
    /// - Parameter bitCount: The number of bits in the RSA key.
    init(bitCount: Int) throws
}

public extension RSAPrivateKey where Self: PKCS1Convertible {
    /// Calculates the RSA public key for the private key.
    ///
    /// The default implementation of the conversion is done by creating a PKCS#1 format of the key and extracting the public key info from this form.
    ///
    /// - Attention: If the key is not a valid RSA private key or cannot be converted to a PKCS#1 format, program execution is stopped via `fatalError`.
    ///
    /// - Returns: A RSA public key instance.
    func publicKey<PK>() -> PK where PK: RSAPublicKey & PKCS1Convertible {
        expectNoError {
            let pkcs1PublicKey = try ASN1.PKCS1.RSAPrivateKey(derData: pkcs1Representation).publicKey()
            return try PK(pkcs1Representation: pkcs1PublicKey.derBytes())
        }
    }
}

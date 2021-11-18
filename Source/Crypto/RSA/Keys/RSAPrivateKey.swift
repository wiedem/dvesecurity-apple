// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
#if canImport(DVESecurity_ObjC)
import DVESecurity_ObjC
#endif

/// A type representing a RSA private key.
public protocol RSAPrivateKey: RSAKey, DefinesSecKeyClass {
    /// Creates a new RSA private key.
    ///
    /// - Parameter bitCount: The number of bits in the RSA key.
    init(bitCount: Int) throws
}

public extension RSAPrivateKey where Self: PKCS1Convertible {
    /// Calculates the RSA public key.
    ///
    /// - Returns: A RSA public key instance.
    func publicKey<PK>() -> PK where PK: RSAPublicKey & PKCS1Convertible {
        expectNoError {
            let asn1PublicKey = try ASN1.RSAPrivateKey(pkcs1Data: pkcs1Representation).publicKey
            let encodedPublicKey = try ASN1.Coder.encode(asn1PublicKey)
            return try PK(pkcs1Representation: encodedPublicKey)
        }
    }
}

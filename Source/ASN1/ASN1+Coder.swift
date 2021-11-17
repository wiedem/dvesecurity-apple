// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
#if canImport(DVESecurity_ObjC)
import DVESecurity_ObjC
#endif

public extension ASN1.Coder {
    class func createX509SubjectPublicKeyInfo<Bytes>(for rsaPublicKey: Bytes) throws -> Data where Bytes: ContiguousBytes {
        try rsaPublicKey.withUnsafeBytes { buffer in
            try __createX509SubjectPublicKeyInfo(Data(buffer))
        }
    }

    class func createX509SubjectPublicKeyInfo<PK>(for rsaPublicKey: PK) throws -> Data where PK: RSAPublicKey & PKCS1Convertible {
        try __createX509SubjectPublicKeyInfo(rsaPublicKey.pkcs1Representation)
    }

    class func extractX509SubjectPublicKey<Bytes>(from x509SubjectPublicKeyInfo: Bytes) throws -> Data where Bytes: ContiguousBytes {
        try x509SubjectPublicKeyInfo.withUnsafeBytes { buffer in
            try __extractX509SubjectPublicKey(Data(buffer))
        }
    }

    class func extractX509SubjectPublicKey<Bytes, PK>(from x509SubjectPublicKeyInfo: Bytes) throws -> PK
        where
        Bytes: ContiguousBytes,
        PK: RSAPublicKey & PKCS1Convertible
    {
        try x509SubjectPublicKeyInfo.withUnsafeBytes { buffer in
            let pkcs1Representation = try __extractX509SubjectPublicKey(Data(buffer))
            return try PK(pkcs1Representation: pkcs1Representation)
        }
    }

    /// Decodes an ASN.1 encoded RSA private key.
    ///
    /// Decodes a RSA private key in its ASN.1 DER encoded format as defined in [RFC 8017 - PKCS #1](https://tools.ietf.org/html/rfc8017#appendix-A.1.2).
    ///
    /// - Returns: A decoded RSA private key instance.
    class func decode<Bytes>(_ asn1Bytes: Bytes) throws -> ASN1.RSAPrivateKey where Bytes: ContiguousBytes {
        try asn1Bytes.withUnsafeBytes { buffer in
            try __decodeRSAPrivateKey(Data(buffer))
        }
    }

    /// Decodes an ASN.1 encoded RSA public key.
    ///
    /// Decodes a RSA public key in its ASN.1 DER encoded format as defined in [RFC 8017 - PKCS #1](https://tools.ietf.org/html/rfc8017#appendix-A.1.1).
    ///
    /// - Returns: A decoded RSA private key instance.
    class func decode<Bytes>(_ asn1Bytes: Bytes) throws -> ASN1.RSAPublicKey where Bytes: ContiguousBytes {
        try asn1Bytes.withUnsafeBytes { buffer in
            try __decodeRSAPublicKey(Data(buffer))
        }
    }
}

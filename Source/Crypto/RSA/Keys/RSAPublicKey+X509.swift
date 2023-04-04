// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import SwiftASN1

public extension RSAPublicKey where Self: X509Convertible & PKCS1Convertible {
    /// The X.509 representation of the RSA public key.
    ///
    /// The format of the data is an ASN.1 DER representation of the key as described in the `SubjectPublicKeyInfo` field definition of the X.509 (PKIX) standard [rfc5912](https://tools.ietf.org/html/rfc5912).
    var x509Representation: Data {
        let subjectPublicKeyInfo = ASN1.X509.SubjectPublicKeyInfo(self)
        var serializer = DER.Serializer()
        expectNoError {
            try serializer.serialize(subjectPublicKeyInfo)
        }
        return Data(serializer.serializedBytes)
    }

    /// Creates a new instance from a X.509 representation of the RSA public key.
    ///
    /// The format of the input data has to be an ASN.1 DER representation of the key as described in the `SubjectPublicKeyInfo` field definition of the X.509 (PKIX) standard [rfc5912](https://tools.ietf.org/html/rfc5912).
    ///
    /// - Parameter x509Representation: ASN.1 DER representation of the key as defined in the X.509 standard.
    init(x509Representation: some ContiguousBytes) throws {
        let node = try x509Representation.withUnsafeBytes {
            try DER.parse(Array($0))
        }
        let subjectPublicKeyInfo = try ASN1.X509.SubjectPublicKeyInfo(derEncoded: node)
        let pkcs1RSAPublicKey = try subjectPublicKeyInfo.pkcs1RSAPublicKey()
        try self.init(pkcs1Representation: pkcs1RSAPublicKey.derBytes())
    }
}

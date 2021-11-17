// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
#if canImport(DVESecurity_ObjC)
import DVESecurity_ObjC
#endif

public extension RSAPublicKey where Self: X509Convertible & PKCS1Convertible {
    /// The X.509 representation of the RSA public key.
    ///
    /// The format of the data is an ASN.1 DER representation of the key as described in the `SubjectPublicKeyInfo` field definition of the X.509 (PKIX) standard [rfc5912](https://tools.ietf.org/html/rfc5912).
    var x509Representation: Data {
        expectNoError {
            try ASN1.Coder.createX509SubjectPublicKeyInfo(for: self)
        }
    }

    /// Creates a new instance from a X.509 representation of the RSA public key.
    ///
    /// The format of the input data has to be an ASN.1 DER representation of the key as described in the `SubjectPublicKeyInfo` field definition of the X.509 (PKIX) standard [rfc5912](https://tools.ietf.org/html/rfc5912).
    ///
    /// - Parameter x509Representation: ASN.1 DER representation of the key as defined in the X.509 standard.
    init<Bytes>(x509Representation: Bytes) throws where Bytes: ContiguousBytes {
        let pkcs1Representation = try ASN1.Coder.extractX509SubjectPublicKey(from: x509Representation)
        try self.init(pkcs1Representation: pkcs1Representation)
    }
}

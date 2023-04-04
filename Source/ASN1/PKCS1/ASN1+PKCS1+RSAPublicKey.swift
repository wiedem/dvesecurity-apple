// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import SwiftASN1

public extension ASN1.PKCS1 {
    /// A RSA public key representation as defined by the PKCS#1 version 2.2 standard.
    ///
    /// This type can be used to convert RSA public keys to a DER encoded form and to generate them from a DER encoded form.
    struct RSAPublicKey {
        public let modulus: ArraySlice<UInt8>
        public let publicExponent: ArraySlice<UInt8>

        public init(modulus: ArraySlice<UInt8>, publicExponent: ArraySlice<UInt8>) {
            self.modulus = modulus
            self.publicExponent = publicExponent
        }
    }
}

public extension ASN1.PKCS1.RSAPublicKey {
    /// Creates a RSA public key instance from DER encoded byte sequence.
    init<S>(derData: S) throws where S: Sequence, S.Element == UInt8 {
        let node = try DER.parse(Array(derData))
        try self.init(derEncoded: node)
    }

    /// Creates a RSA public key instance from DER encoded bytes.
    init(derData: ArraySlice<UInt8>) throws {
        let node = try DER.parse(derData)
        try self.init(derEncoded: node)
    }

    /// Converts the RSA public key to a DER encoded byte sequence.
    func derBytes() throws -> [UInt8] {
        var serializer = DER.Serializer()
        try serializer.serialize(self)
        return serializer.serializedBytes
    }
}

extension ASN1.PKCS1.RSAPublicKey: DERImplicitlyTaggable {
    public static var defaultIdentifier: SwiftASN1.ASN1Identifier {
        .sequence
    }

    public init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let modulus = try ArraySlice<UInt8>(derEncoded: &nodes)
            let publicExponent = try ArraySlice<UInt8>(derEncoded: &nodes)

            return Self(modulus: modulus, publicExponent: publicExponent)
        }
    }

    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(modulus)
            try coder.serialize(publicExponent)
        }
    }
}

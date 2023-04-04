// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import SwiftASN1

public extension ASN1.PKCS1 {
    /// A RSA private key representation as defined by the PKCS#1 version 2.2 standard.
    ///
    /// This type can be used to convert RSA private keys to a DER encoded form and to generate them from a DER encoded form.
    struct RSAPrivateKey {
        public let version: Version
        public let modulus: ArraySlice<UInt8>
        public let publicExponent: ArraySlice<UInt8>
        public let privateExponent: ArraySlice<UInt8>
        public let prime1: ArraySlice<UInt8>
        public let prime2: ArraySlice<UInt8>
        public let exponent1: ArraySlice<UInt8>
        public let exponent2: ArraySlice<UInt8>
        public let coefficient: ArraySlice<UInt8>
        public let otherPrimeInfos: [OtherPrimeInfo]?

        public init(
            version: Version,
            modulus: ArraySlice<UInt8>,
            publicExponent: ArraySlice<UInt8>,
            privateExponent: ArraySlice<UInt8>,
            prime1: ArraySlice<UInt8>,
            prime2: ArraySlice<UInt8>,
            exponent1: ArraySlice<UInt8>,
            exponent2: ArraySlice<UInt8>,
            coefficient: ArraySlice<UInt8>,
            otherPrimeInfos: [OtherPrimeInfo]? = nil
        ) {
            self.version = version
            self.modulus = modulus
            self.publicExponent = publicExponent
            self.privateExponent = privateExponent
            self.prime1 = prime1
            self.prime2 = prime2
            self.exponent1 = exponent1
            self.exponent2 = exponent2
            self.coefficient = coefficient
            self.otherPrimeInfos = otherPrimeInfos
        }

        /// Extract the RSA public key from the private key.
        ///
        /// - Returns: The RSA public key part of the key.
        public func publicKey() -> RSAPublicKey {
            .init(modulus: modulus, publicExponent: publicExponent)
        }
    }
}

public extension ASN1.PKCS1.RSAPrivateKey {
    /// The version of the RSA private key.
    ///
    /// The version of a RSA private key shall be ``twoPrime`` unless ``otherPrimeInfos`` is present in the key.
    enum Version: UInt8, ASN1IntegerRepresentable {
        case twoPrime = 0
        case multiPrime = 1
    }
}

public extension ASN1.PKCS1.RSAPrivateKey {
    struct OtherPrimeInfo {
        public let prime: ArraySlice<UInt8>
        public let exponent: ArraySlice<UInt8>
        public let coefficient: ArraySlice<UInt8>

        public init(prime: ArraySlice<UInt8>, exponent: ArraySlice<UInt8>, coefficient: ArraySlice<UInt8>) {
            self.prime = prime
            self.exponent = exponent
            self.coefficient = coefficient
        }
    }
}

public extension ASN1.PKCS1.RSAPrivateKey {
    /// Creates a RSA private key instance from a DER encoded byte sequence.
    init<S>(derData: S) throws where S: Sequence, S.Element == UInt8 {
        let node = try DER.parse(Array(derData))
        try self.init(derEncoded: node)
    }

    /// Creates a RSA private key instance from DER encoded bytes.
    init(derData: ArraySlice<UInt8>) throws {
        let node = try DER.parse(derData)
        try self.init(derEncoded: node)
    }

    /// Converts the RSA private key to a DER encoded byte sequence.
    func derBytes() throws -> [UInt8] {
        var serializer = DER.Serializer()
        try serializer.serialize(self)
        return serializer.serializedBytes
    }
}

extension ASN1.PKCS1.RSAPrivateKey: DERImplicitlyTaggable {
    /// An error for key related operations.
    public enum KeyError: Error {
        /// The RSA private key has an invalid `version` field.
        case invalidVersion(Version)
    }

    public static var defaultIdentifier: SwiftASN1.ASN1Identifier {
        .sequence
    }

    public init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try Version(derEncoded: &nodes)
            let modulus = try ArraySlice<UInt8>(derEncoded: &nodes)
            let publicExponent = try ArraySlice<UInt8>(derEncoded: &nodes)
            let privateExponent = try ArraySlice<UInt8>(derEncoded: &nodes)
            let prime1 = try ArraySlice<UInt8>(derEncoded: &nodes)
            let prime2 = try ArraySlice<UInt8>(derEncoded: &nodes)
            let exponent1 = try ArraySlice<UInt8>(derEncoded: &nodes)
            let exponent2 = try ArraySlice<UInt8>(derEncoded: &nodes)
            let coefficient = try ArraySlice<UInt8>(derEncoded: &nodes)

            let otherPrimeInfos: [OtherPrimeInfo]? = try DER.optionalImplicitlyTagged(&nodes)

            if let otherPrimeInfos {
                // Version must be `multi` if otherPrimeInfos present.
                guard otherPrimeInfos.isEmpty || version == .multiPrime else {
                    throw KeyError.invalidVersion(version)
                }
            }

            return Self(
                version: version,
                modulus: modulus,
                publicExponent: publicExponent,
                privateExponent: privateExponent,
                prime1: prime1,
                prime2: prime2,
                exponent1: exponent1,
                exponent2: exponent2,
                coefficient: coefficient,
                otherPrimeInfos: otherPrimeInfos
            )
        }
    }

    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(version)
            try coder.serialize(modulus)
            try coder.serialize(publicExponent)
            try coder.serialize(privateExponent)
            try coder.serialize(prime1)
            try coder.serialize(prime2)
            try coder.serialize(exponent1)
            try coder.serialize(exponent2)
            try coder.serialize(coefficient)

            try coder.serializeOptionalImplicitlyTagged(otherPrimeInfos)
        }
    }
}

extension ASN1.PKCS1.RSAPrivateKey.OtherPrimeInfo: DERImplicitlyTaggable {
    public static var defaultIdentifier: SwiftASN1.ASN1Identifier {
        .sequence
    }

    public init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let prime = try ArraySlice<UInt8>(derEncoded: &nodes)
            let exponent = try ArraySlice<UInt8>(derEncoded: &nodes)
            let coefficient = try ArraySlice<UInt8>(derEncoded: &nodes)

            return Self(prime: prime, exponent: exponent, coefficient: coefficient)
        }
    }

    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(prime)
            try coder.serialize(exponent)
            try coder.serialize(coefficient)
        }
    }
}

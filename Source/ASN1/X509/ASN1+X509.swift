// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import SwiftASN1

public extension ASN1 {
    /// A container for X.509 types represented with the ASN.1 standard.
    enum X509 {}
}

public extension ASN1.X509 {
    /// The public key info used by several X.509 types.
    struct SubjectPublicKeyInfo {
        public let algorithm: AlgorithmIdentifier
        public let subjectPublicKey: ASN1BitString

        public init(algorithm: AlgorithmIdentifier, subjectPublicKey: ASN1BitString) {
            self.algorithm = algorithm
            self.subjectPublicKey = subjectPublicKey
        }

        public init(_ rsaPublicKey: some RSAPublicKey & PKCS1Convertible) {
            let subjectPublicKey = expectNoError {
                let pkcs1PublicKey = try ASN1.PKCS1.RSAPublicKey(derData: rsaPublicKey.pkcs1Representation)
                return try ASN1BitString(bytes: ArraySlice(pkcs1PublicKey.derBytes()))
            }

            self.init(algorithm: .rsaPublicKeyIdentifier, subjectPublicKey: subjectPublicKey)
        }
    }
}

public extension ASN1.X509 {
    struct AlgorithmIdentifier {
        public let algorithm: ASN1ObjectIdentifier
        public let parameters: ASN1Node?

        public init(algorithm: ASN1ObjectIdentifier, parameters: ASN1Node? = nil) {
            self.algorithm = algorithm
            self.parameters = parameters
        }
    }
}

public extension ASN1.X509.AlgorithmIdentifier {
    /// The algorithm identifier for RSA public keys.
    static var rsaPublicKeyIdentifier: Self {
        let algorithm = ASN1ObjectIdentifier.AlgorithmIdentifier.rsaEncryption
        return .init(algorithm: algorithm, parameters: nil)
    }
}

extension ASN1.X509.SubjectPublicKeyInfo: DERImplicitlyTaggable {
    public static var defaultIdentifier: SwiftASN1.ASN1Identifier {
        .sequence
    }

    public init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let algorithm = try ASN1.X509.AlgorithmIdentifier(derEncoded: &nodes)
            let subjectPublicKey = try ASN1BitString(derEncoded: &nodes)
            return Self(algorithm: algorithm, subjectPublicKey: subjectPublicKey)
        }
    }

    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(algorithm)
            try coder.serialize(subjectPublicKey)
        }
    }
}

public extension ASN1.X509.SubjectPublicKeyInfo {
    enum KeyError: Error {
        case invalidAlgorithm(ASN1ObjectIdentifier)
        case invalidParameters
    }

    /// Gets a RSA public key from the public key info if the type references a RSA public key.
    func pkcs1RSAPublicKey() throws -> ASN1.PKCS1.RSAPublicKey {
        guard algorithm.algorithm == ASN1ObjectIdentifier.AlgorithmIdentifier.rsaEncryption else {
            throw KeyError.invalidAlgorithm(algorithm.algorithm)
        }
        guard algorithm.parameters == nil else {
            throw KeyError.invalidParameters
        }
        return try ASN1.PKCS1.RSAPublicKey(derData: subjectPublicKey.bytes)
    }
}

extension ASN1.X509.AlgorithmIdentifier: DERImplicitlyTaggable {
    public static var defaultIdentifier: SwiftASN1.ASN1Identifier {
        .sequence
    }

    public init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let algorithm = try ASN1ObjectIdentifier(derEncoded: &nodes)
            return Self(algorithm: algorithm, parameters: nodes.next())
        }
    }

    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(algorithm)
            if let parameters {
                coder.serialize(parameters)
            }
        }
    }
}

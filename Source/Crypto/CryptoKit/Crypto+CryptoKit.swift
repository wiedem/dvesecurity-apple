// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
#if canImport(CryptoKit)
import CryptoKit

@available(iOS 13.0, *)
extension P256.Signing.PrivateKey: ECCPrivateKey & X963Convertible & SecKeyConvertible {}

@available(iOS 13.0, *)
extension P256.Signing.PublicKey: ECCPublicKey & X963Convertible {}

@available(iOS 13.0, *)
extension P256.KeyAgreement.PrivateKey: ECCPrivateKey & X963Convertible & SecKeyConvertible {}

@available(iOS 13.0, *)
extension P256.KeyAgreement.PublicKey: ECCPublicKey & X963Convertible {}

@available(iOS 13.0, *)
extension P384.Signing.PrivateKey: ECCPrivateKey & X963Convertible & SecKeyConvertible {}

@available(iOS 13.0, *)
extension P384.Signing.PublicKey: ECCPublicKey & X963Convertible {}

@available(iOS 13.0, *)
extension P384.KeyAgreement.PrivateKey: ECCPrivateKey & X963Convertible & SecKeyConvertible {}

@available(iOS 13.0, *)
extension P384.KeyAgreement.PublicKey: ECCPublicKey & X963Convertible {}

@available(iOS 13.0, *)
extension P521.Signing.PrivateKey: ECCPrivateKey & X963Convertible & SecKeyConvertible {}

@available(iOS 13.0, *)
extension P521.Signing.PublicKey: ECCPublicKey & X963Convertible {}

@available(iOS 13.0, *)
extension P521.KeyAgreement.PrivateKey: ECCPrivateKey & X963Convertible & SecKeyConvertible {}

@available(iOS 13.0, *)
extension P521.KeyAgreement.PublicKey: ECCPublicKey & X963Convertible {}

@available(iOS 13.0, *)
extension Curve25519.KeyAgreement.PrivateKey: RawKeyConvertible {
    public var rawKeyRepresentation: Data { rawRepresentation }

    public init<Bytes>(rawKeyRepresentation: Bytes) throws where Bytes: ContiguousBytes {
        try self.init(rawRepresentation: rawKeyRepresentation)
    }
}

@available(iOS 13.0, *)
extension Curve25519.Signing.PrivateKey: RawKeyConvertible {
    public var rawKeyRepresentation: Data { rawRepresentation }

    public init<Bytes>(rawKeyRepresentation: Bytes) throws where Bytes: ContiguousBytes {
        try self.init(rawRepresentation: rawKeyRepresentation)
    }
}

@available(iOS 13.0, *)
extension CryptoKit.SymmetricKey: SymmetricKey & RawKeyConvertible {
    public var rawKeyRepresentation: Data { dataNoCopy }

    public init<Bytes>(rawKeyRepresentation: Bytes) where Bytes: ContiguousBytes {
        self.init(data: rawKeyRepresentation)
    }
}

@available(iOS 13.0, *)
extension CryptoKit.SecureEnclave.P256.Signing.PrivateKey: RawKeyConvertible {
    public var rawKeyRepresentation: Data { dataRepresentation }

    public init<Bytes>(rawKeyRepresentation: Bytes) throws where Bytes: ContiguousBytes {
        try self.init(dataRepresentation: rawKeyRepresentation.dataNoCopy, authenticationContext: nil)
    }
}

@available(iOS 13.0, *)
extension CryptoKit.SecureEnclave.P256.KeyAgreement.PrivateKey: RawKeyConvertible {
    public var rawKeyRepresentation: Data { dataRepresentation }

    public init<Bytes>(rawKeyRepresentation: Bytes) throws where Bytes: ContiguousBytes {
        try self.init(dataRepresentation: rawKeyRepresentation.dataNoCopy, authenticationContext: nil)
    }
}

#endif

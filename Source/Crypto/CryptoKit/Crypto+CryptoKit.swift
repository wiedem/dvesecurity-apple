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

    public init(rawKeyRepresentation: some ContiguousBytes) throws {
        try self.init(rawRepresentation: rawKeyRepresentation)
    }
}

@available(iOS 13.0, *)
extension Curve25519.Signing.PrivateKey: RawKeyConvertible {
    public var rawKeyRepresentation: Data { rawRepresentation }

    public init(rawKeyRepresentation: some ContiguousBytes) throws {
        try self.init(rawRepresentation: rawKeyRepresentation)
    }
}

@available(iOS 13.0, *)
extension CryptoKit.SymmetricKey: SymmetricKey & RawKeyConvertible {
    /// The raw representation of the key.
    ///
    /// The raw data of the key is copied in memory and returned as a `Data` Instance.
    public var rawKeyRepresentation: Data {
        withUnsafeBytes { Data($0) }
    }

    /// Creates a key from the given raw representation of the key.
    ///
    /// - Parameter rawKeyRepresentation: Raw representation of the key.
    public init(rawKeyRepresentation: some ContiguousBytes) {
        self.init(data: rawKeyRepresentation)
    }
}

@available(iOS 13.0, *)
extension CryptoKit.SecureEnclave.P256.Signing.PrivateKey: RawKeyConvertible {
    public var rawKeyRepresentation: Data { dataRepresentation }

    /// Creates a P-256 private key for signing from a raw key representation of the key.
    ///
    /// The raw data passed is copied in memory as needed to initialize the key.
    ///
    /// - Parameter rawKeyRepresentation: Raw representation of the key.
    public init(rawKeyRepresentation: some ContiguousBytes) throws {
        let data = rawKeyRepresentation.withUnsafeBytes { Data($0) }
        try self.init(dataRepresentation: data, authenticationContext: nil)
    }
}

@available(iOS 13.0, *)
extension CryptoKit.SecureEnclave.P256.KeyAgreement.PrivateKey: RawKeyConvertible {
    public var rawKeyRepresentation: Data { dataRepresentation }

    /// Creates a P-256 private key for signing from a raw key representation of the key.
    ///
    /// The raw data passed is copied in memory as needed to initialize the key.
    ///
    /// - Parameter rawKeyRepresentation: Raw representation of the key.
    public init(rawKeyRepresentation: some ContiguousBytes) throws {
        let data = rawKeyRepresentation.withUnsafeBytes { Data($0) }
        try self.init(dataRepresentation: data, authenticationContext: nil)
    }
}

#endif

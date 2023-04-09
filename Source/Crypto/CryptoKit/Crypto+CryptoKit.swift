// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
#if canImport(CryptoKit)
import CryptoKit

extension P256.Signing.PrivateKey: ECCPrivateKey & X963Convertible & SecKeyConvertible {}

extension P256.Signing.PublicKey: ECCPublicKey & X963Convertible {}

extension P256.KeyAgreement.PrivateKey: ECCPrivateKey & X963Convertible & SecKeyConvertible {}

extension P256.KeyAgreement.PublicKey: ECCPublicKey & X963Convertible {}

extension P384.Signing.PrivateKey: ECCPrivateKey & X963Convertible & SecKeyConvertible {}

extension P384.Signing.PublicKey: ECCPublicKey & X963Convertible {}

extension P384.KeyAgreement.PrivateKey: ECCPrivateKey & X963Convertible & SecKeyConvertible {}

extension P384.KeyAgreement.PublicKey: ECCPublicKey & X963Convertible {}

extension P521.Signing.PrivateKey: ECCPrivateKey & X963Convertible & SecKeyConvertible {}

extension P521.Signing.PublicKey: ECCPublicKey & X963Convertible {}

extension P521.KeyAgreement.PrivateKey: ECCPrivateKey & X963Convertible & SecKeyConvertible {}

extension P521.KeyAgreement.PublicKey: ECCPublicKey & X963Convertible {}

extension Curve25519.KeyAgreement.PrivateKey: KeyDataRepresentable {
    public var keyData: Crypto.KeyData {
        .createFromUnsafeData(rawRepresentation)
    }

    public init(keyData: Crypto.KeyData) throws {
        self = try keyData.withUnsafeBytes {
            try Self(rawRepresentation: $0)
        }
    }
}

extension Curve25519.Signing.PrivateKey: KeyDataRepresentable {
    public var keyData: Crypto.KeyData {
        .createFromUnsafeData(rawRepresentation)
    }

    public init(keyData: Crypto.KeyData) throws {
        self = try keyData.withUnsafeBytes {
            try Self(rawRepresentation: $0)
        }
    }
}

extension CryptoKit.SymmetricKey: KeyDataRepresentable {
    public var keyData: Crypto.KeyData {
        .createFromUnsafeBytes(self)
    }

    public init(keyData: Crypto.KeyData) {
        self = keyData.withUnsafeBytes {
            Self(data: $0)
        }
    }
}

extension CryptoKit.SecureEnclave.P256.Signing.PrivateKey: KeyDataRepresentable {
    public var keyData: Crypto.KeyData {
        .createFromUnsafeData(dataRepresentation)
    }

    public init(keyData: Crypto.KeyData) throws {
        self = try keyData.withUnsafeBytes {
            try Self(dataRepresentation: Data($0))
        }
    }
}

extension CryptoKit.SecureEnclave.P256.KeyAgreement.PrivateKey: KeyDataRepresentable {
    public var keyData: Crypto.KeyData {
        .createFromUnsafeData(dataRepresentation)
    }

    public init(keyData: Crypto.KeyData) throws {
        self = try keyData.withUnsafeBytes {
            try Self(dataRepresentation: Data($0))
        }
    }
}

#endif

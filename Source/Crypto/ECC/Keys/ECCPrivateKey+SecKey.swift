// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

public extension ECCPrivateKey {
    static var secKeyClass: SecKeyClass { .private(.ellipticCurve) }
}

public extension ECCPrivateKey where Self: ConvertibleToSecKey {
    /// Decrypts a block of data using this key and the specified ECC algorithm.
    ///
    /// - Parameters:
    ///   - cipherText: The ciphertext data to decrypt.
    ///   - algorithm: Algorithm used to perform the decryption. See  ``Crypto/ECC/EncryptionAlgorithm`` for more details.
    ///
    /// - Returns: The decrypted plaintext data.
    func decrypt(_ cipherText: some DataProtocol, using algorithm: Crypto.ECC.EncryptionAlgorithm) throws -> Data {
        return try Crypto.ECC.decrypt(cipherText, withKey: self, algorithm: algorithm)
    }

    /// Generates an ECC signature of the given data using the given algorithm.
    ///
    /// - Parameters:
    ///   - data: The data to sign.
    ///   - algorithm: The algorithm to use for the signature.
    ///
    /// - Returns: The signature corresponding to the data.
    func signature(for data: some DataProtocol, algorithm: Crypto.ECC.SignatureAlgorithm) throws -> Data {
        return try Crypto.ECC.sign(data, withKey: self, algorithm: algorithm)
    }
}

public extension ECCPrivateKey where Self: ConvertibleToSecKey {
    /// Calculates the ECC public key.
    ///
    /// - Returns: A ECC public key instance.
    func publicKey<PK>() -> PK where PK: ECCPublicKey & CreateableFromSecKey {
        expectNoError {
            try PK(privateKey: self)
        }
    }
}

public extension ECCPrivateKey where Self: SecKeyConvertible & X963Convertible {
    /// Creates a ECC private key instance from a given `SecKey`.
    ///
    /// - Parameter secKey: The `SecKey` from which the ECC private key should be created.
    ///
    /// - Throws: ``Crypto/KeyError/invalidSecKey`` if the SecKey is no valid ECC private key.
    init(secKey: SecKey) throws {
        let (secKeyClass, secKeyAttributes) = Self.secKeyAttributes(for: secKey)
        guard let keyClass = secKeyClass, keyClass == Self.secKeyClass else {
            throw Crypto.KeyError.invalidSecKey
        }
        guard secKeyAttributes?.isBackedBySecureEnclave != true else {
            throw Crypto.KeyError.invalidSecKey
        }

        let data = try secKey.externalRepresentation()
        try self.init(x963Representation: data)
    }
}

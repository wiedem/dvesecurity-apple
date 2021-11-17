// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

public extension RSAPrivateKey {
    static var secKeyClass: SecKeyClass { .private(.RSA) }
}

public extension RSAPrivateKey where Self: ConvertibleToSecKey {
    /// Decrypts a block of data using this key and the specified RSA algorithm.
    ///
    /// - Parameters:
    ///   - cipherText: The ciphertext data to decrypt.
    ///   - algorithm: Algorithm used to perform the decryption. See  ``Crypto/RSA/EncryptionAlgorithm`` for more details.
    ///
    /// - Throws: ``Crypto/RSAError/invalidDataLength`` if the data length of the plaintext doesn't meet the requirements of the key and algorithm.
    ///
    /// - Returns: The decrypted plaintext data.
    func decrypt<D>(_ cipherText: D, using algorithm: Crypto.RSA.EncryptionAlgorithm) throws -> Data where D: DataProtocol {
        return try Crypto.RSA.decrypt(cipherText, withKey: self, algorithm: algorithm)
    }

    /// Generates an RSA signature of the given data using the given algorithm.
    ///
    /// - Parameters:
    ///   - data: The data to sign.
    ///   - algorithm: The algorithm to use for the signature.
    ///
    /// - Returns: The signature corresponding to the data.
    func signature<D>(for data: D, algorithm: Crypto.RSA.SignatureAlgorithm) throws -> Data where D: DataProtocol {
        return try Crypto.RSA.sign(data, withKey: self, algorithm: algorithm)
    }
}

public extension RSAPrivateKey where Self: ConvertibleToSecKey {
    /// Calculates the RSA public key.
    ///
    /// - Returns: A RSA public key instance.
    func publicKey<PK>() -> PK where PK: RSAPublicKey & CreateableFromSecKey {
        expectNoError {
            try PK(privateKey: self)
        }
    }
}

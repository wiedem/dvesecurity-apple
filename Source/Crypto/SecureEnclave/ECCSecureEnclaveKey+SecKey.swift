// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

public extension ECCSecureEnclaveKey {
    static var secKeyClass: SecKeyClass { .private(.ellipticCurve) }
}

public extension ECCSecureEnclaveKey where Self: ConvertibleToSecKey & CustomDebugStringConvertible {
    var debugDescription: String { "\(secKey)" }
}

public extension ECCSecureEnclaveKey where Self: ConvertibleToSecKey {
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

public extension ECCSecureEnclaveKey where Self: ConvertibleToSecKey {
    /// Calculates the ECC public key.
    ///
    /// - Returns: An ECC public key instance.
    func publicKey<PK>() -> PK where PK: ECCPublicKey & CreateableFromSecKey {
        expectNoError {
            try PK(secureEnclaveKey: self)
        }
    }
}

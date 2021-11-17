// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

public extension ECCPublicKey {
    static var secKeyClass: SecKeyClass { .public(.ECSECPrimeRandom) }
}

public extension ECCPublicKey where Self: ConvertibleToSecKey {
    /// Encrypts a block of data using this key and the specified ECC algorithm.
    ///
    /// - Parameters:
    ///   - plainText: The plaintext data to encrypt.
    ///   - algorithm: Algorithm used to perform the encryption. See ``Crypto/ECC/EncryptionAlgorithm`` for more details.
    ///
    /// - Returns: The ciphertext represented as a Data object.
    func encrypt<D>(_ plainText: D, using algorithm: Crypto.ECC.EncryptionAlgorithm) throws -> Data where D: DataProtocol {
        return try Crypto.ECC.encrypt(plainText, withKey: self, algorithm: algorithm)
    }

    /// Verifies an ECC signature on a block of data with the given algorithm.
    ///
    /// - Parameters:
    ///   - signature: The signature to check against the given data.
    ///   - data: The data covered by the signature.
    ///   - algorithm: The algorithm used for the signature.
    ///
    /// - Returns: A Boolean value that’s `true` if the signature is valid for the given data.
    func isValidSignature<D>(_ signature: Data, for data: D, algorithm: Crypto.ECC.SignatureAlgorithm) throws -> Bool where D: DataProtocol {
        return try Crypto.ECC.verifySignature(signature, of: data, withKey: self, algorithm: algorithm)
    }
}

public extension ECCPublicKey where Self: CreateableFromSecKey {
    /// Creates an ECC public key from an ECC private key.
    ///
    /// - Parameter privateKey: ECC private key used to dervice the public key from.
    init<K>(privateKey: K) throws where K: ECCPrivateKey & ConvertibleToSecKey {
        let publicSecKey = try Crypto.Asymmetric.publicKey(for: privateKey.secKey)
        try self.init(secKey: publicSecKey)
    }
}

public extension ECCPublicKey where Self: CreateableFromSecKey {
    /// Creates an ECC public key from an ECC Secure Enclave key.
    ///
    /// - Parameter privateKey: ECC Secure Enclave key used to dervice the public key from.
    init<K>(secureEnclaveKey: K) throws where K: ECCSecureEnclaveKey & ConvertibleToSecKey {
        let publicSecKey = try Crypto.Asymmetric.publicKey(for: secureEnclaveKey.secKey)
        try self.init(secKey: publicSecKey)
    }
}

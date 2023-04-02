// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

public extension ECCPublicKey {
    static var secKeyClass: SecKeyClass { .public(.ellipticCurve) }
}

public extension ECCPublicKey where Self: ConvertibleToSecKey {
    /// Encrypts a block of data using this key and the specified ECC algorithm.
    ///
    /// - Parameters:
    ///   - plainText: The plaintext data to encrypt.
    ///   - algorithm: Algorithm used to perform the encryption. See ``Crypto/ECC/EncryptionAlgorithm`` for more details.
    ///
    /// - Returns: The ciphertext represented as a Data object.
    func encrypt(_ plainText: some DataProtocol, using algorithm: Crypto.ECC.EncryptionAlgorithm) throws -> Data {
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
    func isValidSignature(_ signature: Data, for data: some DataProtocol, algorithm: Crypto.ECC.SignatureAlgorithm) throws -> Bool {
        return try Crypto.ECC.verifySignature(signature, of: data, withKey: self, algorithm: algorithm)
    }
}

public extension ECCPublicKey where Self: CreateableFromSecKey {
    /// Creates an ECC public key from an ECC private key.
    ///
    /// - Parameter privateKey: ECC private key used to dervice the public key from.
    init(privateKey: some ECCPrivateKey & ConvertibleToSecKey) throws {
        let publicSecKey = try Crypto.Asymmetric.publicKey(for: privateKey.secKey)
        try self.init(secKey: publicSecKey)
    }
}

public extension ECCPublicKey where Self: CreateableFromSecKey {
    /// Creates an ECC public key from an ECC Secure Enclave key.
    ///
    /// - Parameter privateKey: ECC Secure Enclave key used to dervice the public key from.
    init(secureEnclaveKey: some ECCSecureEnclaveKey & ConvertibleToSecKey) throws {
        let publicSecKey = try Crypto.Asymmetric.publicKey(for: secureEnclaveKey.secKey)
        try self.init(secKey: publicSecKey)
    }
}

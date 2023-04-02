// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

public extension RSAPublicKey {
    static var secKeyClass: SecKeyClass { .public(.rsa) }
}

public extension RSAPublicKey where Self: ConvertibleToSecKey {
    /// Encrypts a block of data using this key and the specified RSA algorithm.
    ///
    /// - Parameters:
    ///   - plainText: The plaintext data to encrypt.
    ///   - algorithm: Algorithm used to perform the encryption. See ``Crypto/RSA/EncryptionAlgorithm`` for more details.
    ///
    /// - Throws:``Crypto/RSAError/invalidDataLength`` if the data length of the plaintext doesn't meet the requirements of the key and algorithm.
    ///
    /// - Returns: The ciphertext represented as a Data object.
    func encrypt(_ plainText: some DataProtocol, using algorithm: Crypto.RSA.EncryptionAlgorithm) throws -> Data {
        try Crypto.RSA.encrypt(plainText, withKey: self, algorithm: algorithm)
    }

    /// Verifies an RSA signature on a block of data with the given algorithm.
    ///
    /// - Parameters:
    ///   - signature: The signature to check against the given data.
    ///   - data: The data covered by the signature.
    ///   - algorithm: The algorithm used for the signature.
    ///
    /// - Returns: A Boolean value that’s `true` if the signature is valid for the given data.
    func isValidSignature(
        _ signature: Data,
        of data: some DataProtocol,
        algorithm: Crypto.RSA.MessageSignatureAlgorithm
    ) throws -> Bool {
        try Crypto.RSA.verifySignature(signature, of: data, withKey: self, algorithm: algorithm)
    }

    /// Verifies an RSA signature on a block of digest data with the given algorithm.
    ///
    /// - Parameters:
    ///   - signature: The signature to check against the given data.
    ///   - data: The digest data covered by the signature.
    ///   - algorithm: The algorithm used for the signature.
    ///
    /// - Returns: A Boolean value that’s `true` if the signature is valid for the given data.
    func isValidDigestSignature(
        _ signature: Data,
        digest: some DataProtocol,
        algorithm: Crypto.RSA.DigestSignatureAlgorithm
    ) throws -> Bool {
        try Crypto.RSA.verifyDigestSignature(signature, of: digest, withKey: self, algorithm: algorithm)
    }
}

public extension RSAPublicKey where Self: CreateableFromSecKey {
    /// Creates a new RSA public key instance from a given RSA private key.
    ///
    /// - Parameter privateKey: The private key from which the public key should be derived.
    init(privateKey: some RSAPrivateKey & ConvertibleToSecKey) throws {
        let publicSecKey = try Crypto.Asymmetric.publicKey(for: privateKey.secKey)
        try self.init(secKey: publicSecKey)
    }
}

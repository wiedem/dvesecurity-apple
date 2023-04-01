// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

public extension Crypto.RSA {
    /// Encrypts a block of data using an RSA public key and the specified RSA algorithm.
    ///
    /// - Note: The length of the input data may be limited, depending on the algorithm and key used.
    /// See the ``RSAKey/maxPlainTextLength(for:)-2z0eu`` and ``EncryptionAlgorithm`` for further details.
    ///
    /// - Parameters:
    ///   - plainText: The plaintext data to encrypt.
    ///   - publicKey: RSA public key used for the encryption..
    ///   - algorithm: Algorithm used to perform the encryption. See ``EncryptionAlgorithm`` for more details.
    ///
    /// - Throws: ``Crypto/RSAError/invalidDataLength`` if the data length of the plaintext doesn't meet the requirements of the key and algorithm.
    ///
    /// - Returns: The ciphertext represented as a Data object.
    static func encrypt<D, K>(
        _ plainText: D,
        withKey publicKey: K,
        algorithm: EncryptionAlgorithm
    ) throws -> Data where D: DataProtocol, K: RSAPublicKey & ConvertibleToSecKey {
        if let maxPlainTextLength = publicKey.maxPlainTextLength(for: algorithm) {
            guard plainText.count <= maxPlainTextLength else {
                throw Crypto.RSAError.invalidDataLength
            }
        }
        return try Crypto.Asymmetric.encryptDataBlock(plainText, withKey: publicKey.secKey, algorithm: algorithm.secKeyAlgorithm)
    }

    /// Decrypts a block of data using an RSA private key and the specified RSA algorithm.
    ///
    /// - Parameters:
    ///   - cipherText: The ciphertext data to decrypt.
    ///   - privateKey: RSA private key used for the decryption.
    ///   - algorithm: Algorithm used to perform the decryption. See ``EncryptionAlgorithm`` for more details.
    ///
    /// - Throws: ``Crypto/RSAError/invalidDataLength`` if the data length of the plaintext doesn't meet the requirements of the key and algorithm.
    ///
    /// - Returns: The decrypted plaintext data.
    static func decrypt<D, PK>(
        _ cipherText: D,
        withKey privateKey: PK,
        algorithm: EncryptionAlgorithm
    ) throws -> Data where D: DataProtocol, PK: RSAPrivateKey & ConvertibleToSecKey {
        if privateKey.maxPlainTextLength(for: algorithm) != nil {
            guard cipherText.count <= privateKey.blockSize else {
                throw Crypto.RSAError.invalidDataLength
            }
        }
        return try Crypto.Asymmetric.decryptDataBlock(cipherText, withKey: privateKey.secKey, algorithm: algorithm.secKeyAlgorithm)
    }

    /// Creates the cryptographic RSA signature for a block of data using a private key and specified algorithm.
    ///
    /// - Parameters:
    ///   - data: The message data whose signature you want.
    ///   - privateKey: The RSA private key to use in creating the signature.
    ///   - algorithm: The RSA signing algorithm to use. See ``MessageSignatureAlgorithm`` for more details.
    ///
    /// - Returns: The digital signature.
    static func sign<D, PK>(
        _ data: D,
        withKey privateKey: PK,
        algorithm: MessageSignatureAlgorithm
    ) throws -> Data where D: DataProtocol, PK: RSAPrivateKey & ConvertibleToSecKey {
        return try Crypto.Asymmetric.sign(data, withKey: privateKey.secKey, algorithm: algorithm.secKeyAlgorithm)
    }

    /// Creates the cryptographic RSA signature for a digest data using a private key and specified algorithm.
    ///
    /// - Parameters:
    ///   - digestData: The digest data whose signature you want.
    ///   - privateKey: The RSA private key to use in creating the signature.
    ///   - algorithm: The RSA signing algorithm to use. See ``DigestSignatureAlgorithm`` for more details.
    ///
    /// - Returns: The digital signature.
    static func signDigest<D, PK>(
        _ digestData: D,
        withKey privateKey: PK,
        algorithm: DigestSignatureAlgorithm
    ) throws -> Data where D: DataProtocol, PK: RSAPrivateKey & ConvertibleToSecKey {
        return try Crypto.Asymmetric.sign(digestData, withKey: privateKey.secKey, algorithm: algorithm.secKeyAlgorithm)
    }

    /// Verifies the RSA cryptographic signature of a block of data using a public key and specified algorithm.
    ///
    /// - Parameters:
    ///   - signature: The signature that was created with a call to the ``sign(_:withKey:algorithm:)``  function.
    ///   - signedData: The message data that was signed.
    ///   - publicKey: The RSA public key to use in evaluating the signature.
    ///   - algorithm: The algorithm that was used to create the signature. See ``MessageSignatureAlgorithm`` for more details.
    ///
    /// - Returns: A Boolean indicating whether or not the data and signature are intact.
    static func verifySignature<D, K>(
        _ signature: Data,
        of signedData: D,
        withKey publicKey: K,
        algorithm: MessageSignatureAlgorithm
    ) throws -> Bool where D: DataProtocol, K: RSAPublicKey & ConvertibleToSecKey {
        return try Crypto.Asymmetric.verify(
            signature: signature,
            of: signedData,
            withKey: publicKey.secKey,
            algorithm: algorithm.secKeyAlgorithm
        )
    }

    /// Verifies the RSA cryptographic signature of a digest data using a public key and specified algorithm.
    ///
    /// - Parameters:
    ///   - signature: The signature that was created with a call to the  ``signDigest(_:withKey:algorithm:)`` function.
    ///   - signedData: The digest data that was signed.
    ///   - publicKey: The RSA public key to use in evaluating the signature.
    ///   - algorithm: The algorithm that was used to create the signature. See ``DigestSignatureAlgorithm`` for more details.
    ///
    /// - Returns: A Boolean indicating whether or not the data and signature are intact.
    static func verifyDigestSignature<D, K>(
        _ signature: Data,
        of signedDigestData: D,
        withKey publicKey: K,
        algorithm: DigestSignatureAlgorithm
    ) throws -> Bool where D: DataProtocol, K: RSAPublicKey & ConvertibleToSecKey {
        return try Crypto.Asymmetric.verify(
            signature: signature,
            of: signedDigestData,
            withKey: publicKey.secKey,
            algorithm: algorithm.secKeyAlgorithm
        )
    }
}

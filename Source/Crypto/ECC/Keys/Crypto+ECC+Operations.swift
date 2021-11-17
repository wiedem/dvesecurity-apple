// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

public extension Crypto.ECC {
    /// Encrypts a block of data using an ECC public key and the specified ECC algorithm.
    ///
    /// - Parameters:
    ///   - plainText: The plaintext data to encrypt.
    ///   - publicKey: ECC public key used for the encryption..
    ///   - algorithm: Algorithm used to perform the encryption. See ``EncryptionAlgorithm`` for more details.
    ///
    /// - Returns: The ciphertext represented as a Data object.
    static func encrypt<D, K>(
        _ plainText: D,
        withKey publicKey: K,
        algorithm: EncryptionAlgorithm
    ) throws -> Data where D: DataProtocol, K: ECCPublicKey & ConvertibleToSecKey {
        return try Crypto.Asymmetric.encryptDataBlock(plainText, withKey: publicKey.secKey, algorithm: algorithm.secKeyAlgorithm)
    }

    /// Decrypts a block of data using an ECC private key and the specified ECC algorithm.
    ///
    /// - Parameters:
    ///   - cipherText: The ciphertext data to decrypt.
    ///   - privateKey: ECC private key used for the decryption.
    ///   - algorithm: Algorithm used to perform the decryption. See ``EncryptionAlgorithm`` for more details.
    ///
    /// - Returns: The decrypted plaintext data.
    static func decrypt<D, PK>(
        _ cipherText: D,
        withKey privateKey: PK,
        algorithm: EncryptionAlgorithm
    ) throws -> Data where D: DataProtocol, PK: ECCPrivateKey & ConvertibleToSecKey {
        return try Crypto.Asymmetric.decryptDataBlock(cipherText, withKey: privateKey.secKey, algorithm: algorithm.secKeyAlgorithm)
    }

    /// Creates the cryptographic ECC signature for a block of data using a private key and specified algorithm.
    ///
    /// - Parameters:
    ///   - data: The data whose signature you want.
    ///   - privateKey: The ECC private key to use in creating the signature.
    ///   - algorithm: The ECC signing algorithm to use. See ``SignatureAlgorithm`` for more details.
    ///
    /// - Returns: The digital signature.
    static func sign<D, PK>(
        _ data: D,
        withKey privateKey: PK,
        algorithm: SignatureAlgorithm
    ) throws -> Data where D: DataProtocol, PK: ECCPrivateKey & ConvertibleToSecKey {
        return try Crypto.Asymmetric.sign(data, withKey: privateKey.secKey, algorithm: algorithm.secKeyMessageAlgorithm)
    }

    /// Creates the cryptographic ECC signature for a digest data using a private key and specified algorithm.
    ///
    /// - Parameters:
    ///   - digestData: The digest data whose signature you want.
    ///   - privateKey: The ECC private key to use in creating the signature.
    ///   - algorithm: The ECC signing algorithm to use. See ``SignatureAlgorithm`` for more details.
    ///
    /// - Returns: The digital signature.
    static func signDigest<PK>(
        _ digestData: Data,
        withKey privateKey: PK,
        algorithm: SignatureAlgorithm
    ) throws -> Data where PK: ECCPrivateKey & ConvertibleToSecKey {
        return try Crypto.Asymmetric.sign(digestData, withKey: privateKey.secKey, algorithm: algorithm.secKeyDigestAlgorithm)
    }

    /// Verifies the ECC cryptographic signature of a block of data using a public key and specified algorithm.
    ///
    /// - Parameters:
    ///   - signature: The signature that was created with a call to the `sign(_:withKey:algorithm:)` or `signDigest(_:withKey:algorithm:)` function.
    ///   - signedData: The data that was signed.
    ///   - publicKey: The ECC public key to use in evaluating the signature.
    ///   - algorithm: The algorithm that was used to create the signature. See ``SignatureAlgorithm`` for more details.
    ///
    /// - Returns: A Boolean indicating whether or not the data and signature are intact.
    static func verifySignature<D, K>(
        _ signature: Data,
        of signedData: D,
        withKey publicKey: K,
        algorithm: SignatureAlgorithm
    ) throws -> Bool where D: DataProtocol, K: ECCPublicKey & ConvertibleToSecKey {
        return try Crypto.Asymmetric.verify(signature: signature,
                                            of: signedData,
                                            withKey: publicKey.secKey,
                                            algorithm: algorithm.secKeyMessageAlgorithm)
    }
}

public extension Crypto.ECC {
    /// Decrypts a block of data using a Secure Enclave key and the specified ECC algorithm.
    ///
    /// - Parameters:
    ///   - cipherText: The ciphertext data to decrypt.
    ///   - privateKey: Secure Enclave key used for the decryption.
    ///   - algorithm: Algorithm used to perform the decryption. See ``EncryptionAlgorithm`` for more details.
    ///
    /// - Returns: The decrypted plaintext data.
    static func decrypt<D, PK>(
        _ cipherText: D,
        withKey key: PK,
        algorithm: EncryptionAlgorithm
    ) throws -> Data where D: DataProtocol, PK: ECCSecureEnclaveKey & ConvertibleToSecKey {
        return try Crypto.Asymmetric.decryptDataBlock(cipherText, withKey: key.secKey, algorithm: algorithm.secKeyAlgorithm)
    }

    /// Creates the cryptographic ECC signature for a block of data using a Secure Enclave private key and specified algorithm.
    ///
    /// - Parameters:
    ///   - data: The data whose signature you want.
    ///   - privateKey: The ECC Secure Enclave private key to use in creating the signature.
    ///   - algorithm: The ECC signing algorithm to use. See ``SignatureAlgorithm`` for more details.
    ///
    /// - Returns: The digital signature.
    static func sign<D, PK>(
        _ data: D,
        withKey key: PK,
        algorithm: SignatureAlgorithm
    ) throws -> Data where D: DataProtocol, PK: ECCSecureEnclaveKey & ConvertibleToSecKey {
        return try Crypto.Asymmetric.sign(data, withKey: key.secKey, algorithm: algorithm.secKeyMessageAlgorithm)
    }

    /// Creates the cryptographic ECC signature for a digest data using a Secure Enclave private key and specified algorithm.
    ///
    /// - Parameters:
    ///   - digestData: The digest data whose signature you want.
    ///   - privateKey: The ECC Secure Enclave private key to use in creating the signature.
    ///   - algorithm: The ECC signing algorithm to use. See ``SignatureAlgorithm`` for more details.
    ///
    /// - Returns: The digital signature.
    static func signDigest<PK>(
        _ digestData: Data,
        withKey key: PK,
        algorithm: SignatureAlgorithm
    ) throws -> Data where PK: ECCSecureEnclaveKey & ConvertibleToSecKey {
        return try Crypto.Asymmetric.sign(digestData, withKey: key.secKey, algorithm: algorithm.secKeyDigestAlgorithm)
    }
}

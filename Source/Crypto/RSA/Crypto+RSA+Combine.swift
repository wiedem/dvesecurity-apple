// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
#if canImport(Combine)
import Combine

@available(iOS 13.0, *)
extension Crypto.RSA {
    /// Returns a publisher that encrypts a block of data using an RSA public key and the specified RSA algorithm.
    ///
    /// - Note: The length of the input data may be limited, depending on the algorithm and key used.
    /// See ``RSAKey/maxPlainTextLength(for:)-6o9fs`` and ``EncryptionAlgorithm/maxPlainTextLength(for:)`` for further details.
    ///
    /// - Parameters:
    ///   - plainText: The plaintext data to encrypt.
    ///   - publicKey: RSA public key used for the encryption..
    ///   - algorithm: Algorithm used to perform the encryption. See ``EncryptionAlgorithm`` for more details.
    func encryptPublisher<D, K>(
        for plainText: D,
        withKey publicKey: K,
        algorithm: EncryptionAlgorithm
    ) -> AnyPublisher<Data, Error>
        where
        D: DataProtocol,
        K: RSAPublicKey & ConvertibleToSecKey
    {
        Future { promise in
            do {
                let cipherText = try Crypto.RSA.encrypt(plainText, withKey: publicKey, algorithm: algorithm)
                promise(.success(cipherText))
            } catch {
                promise(.failure(error))
            }
        }
        .eraseToAnyPublisher()
    }

    /// Returns a publisher that decrypts a block of data using an RSA private key and the specified RSA algorithm.
    ///
    /// - Parameters:
    ///   - cipherText: The ciphertext data to decrypt.
    ///   - privateKey: RSA private key used for the decryption.
    ///   - algorithm: Algorithm used to perform the decryption. See ``EncryptionAlgorithm`` for more details.
    func decryptPublisher<D, PK>(
        for cipherText: D,
        withKey privateKey: PK,
        algorithm: EncryptionAlgorithm
    ) -> AnyPublisher<Data, Error>
        where
        D: DataProtocol,
        PK: RSAPrivateKey & ConvertibleToSecKey
    {
        Future { promise in
            do {
                let plainText = try Crypto.RSA.decrypt(cipherText, withKey: privateKey, algorithm: algorithm)
                promise(.success(plainText))
            } catch {
                promise(.failure(error))
            }
        }
        .eraseToAnyPublisher()
    }

    /// Returns a publisher that creates the cryptographic RSA signature for a block of data using a private key and specified algorithm.
    ///
    /// - Parameters:
    ///   - data: The data whose signature you want.
    ///   - privateKey: The RSA private key to use in creating the signature.
    ///   - algorithm: The RSA signing algorithm to use. See ``MessageSignatureAlgorithm`` for more details.
    func signPublisher<D, PK>(
        for data: D,
        withKey privateKey: PK,
        algorithm: MessageSignatureAlgorithm
    ) -> AnyPublisher<Data, Error>
        where
        D: DataProtocol,
        PK: RSAPrivateKey & ConvertibleToSecKey
    {
        Future { promise in
            do {
                let signature = try Crypto.RSA.sign(data, withKey: privateKey, algorithm: algorithm)
                promise(.success(signature))
            } catch {
                promise(.failure(error))
            }
        }
        .eraseToAnyPublisher()
    }

    /// Returns a publisher that creates the cryptographic RSA signature for a digest data using a private key and specified algorithm.
    ///
    /// - Parameters:
    ///   - digestData: The digest data whose signature you want.
    ///   - privateKey: The RSA private key to use in creating the signature.
    ///   - algorithm: The RSA signing algorithm to use. See ``DigestSignatureAlgorithm`` for more details.
    func signDigestPublisher<PK>(
        for digestData: Data,
        withKey privateKey: PK,
        algorithm: DigestSignatureAlgorithm
    ) -> AnyPublisher<Data, Error>
        where
        PK: RSAPrivateKey & ConvertibleToSecKey
    {
        Future { promise in
            do {
                let signature = try Crypto.RSA.signDigest(digestData, withKey: privateKey, algorithm: algorithm)
                promise(.success(signature))
            } catch {
                promise(.failure(error))
            }
        }
        .eraseToAnyPublisher()
    }

    /// Returns a publisher that cerifies the RSA cryptographic signature of a block of data using a public key and specified algorithm.
    ///
    /// - Parameters:
    ///   - signature: The signature that was created with a call to the `sign(_:withKey:algorithm:)` or `signDigest(_:withKey:algorithm:)` function.
    ///   - signedData: The data that was signed.
    ///   - publicKey: The RSA public key to use in evaluating the signature.
    ///   - algorithm: The algorithm that was used to create the signature. See ``MessageSignatureAlgorithm`` for more details.
    func verifySignaturePublisher<D, K>(
        for signature: Data,
        of signedData: D,
        withKey publicKey: K,
        algorithm: MessageSignatureAlgorithm
    ) -> AnyPublisher<Bool, Error>
        where
        D: DataProtocol,
        K: RSAPublicKey & ConvertibleToSecKey
    {
        Future { promise in
            do {
                let verified = try Crypto.RSA.verifySignature(signature, of: signedData, withKey: publicKey, algorithm: algorithm)
                promise(.success(verified))
            } catch {
                promise(.failure(error))
            }
        }
        .eraseToAnyPublisher()
    }
}
#endif

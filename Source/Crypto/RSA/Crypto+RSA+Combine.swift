// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
#if canImport(Combine)
import Combine

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
    func encryptPublisher(
        for plainText: some DataProtocol,
        withKey publicKey: some RSAPublicKey & ConvertibleToSecKey,
        algorithm: EncryptionAlgorithm
    ) -> AnyPublisher<Data, Error> {
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
    func decryptPublisher(
        for cipherText: some DataProtocol,
        withKey privateKey: some RSAPrivateKey & ConvertibleToSecKey,
        algorithm: EncryptionAlgorithm
    ) -> AnyPublisher<Data, Error> {
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
    func signPublisher(
        for data: some DataProtocol,
        withKey privateKey: some RSAPrivateKey & ConvertibleToSecKey,
        algorithm: MessageSignatureAlgorithm
    ) -> AnyPublisher<Data, Error> {
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
    func signDigestPublisher(
        for digestData: Data,
        withKey privateKey: some RSAPrivateKey & ConvertibleToSecKey,
        algorithm: DigestSignatureAlgorithm
    ) -> AnyPublisher<Data, Error> {
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
    func verifySignaturePublisher(
        for signature: Data,
        of signedData: some DataProtocol,
        withKey publicKey: some RSAPublicKey & ConvertibleToSecKey,
        algorithm: MessageSignatureAlgorithm
    ) -> AnyPublisher<Bool, Error> {
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

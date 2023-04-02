// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
#if canImport(Combine)
import Combine

@available(iOS 13.0, *)
extension Crypto.ECC {
    /// Returns a publisher that encrypts a block of data using an ECC public key and the specified ECC algorithm.
    ///
    /// - Parameters:
    ///   - plainText: The plaintext data to encrypt.
    ///   - publicKey: ECC public key used for the encryption..
    ///   - algorithm: Algorithm used to perform the encryption. See ``EncryptionAlgorithm`` for more details.
    func encryptPublisher(
        for plainText: some DataProtocol,
        withKey publicKey: some ECCPublicKey & ConvertibleToSecKey,
        algorithm: EncryptionAlgorithm
    ) -> AnyPublisher<Data, Error> {
        Future { promise in
            do {
                let cipherText = try Crypto.ECC.encrypt(plainText, withKey: publicKey, algorithm: algorithm)
                promise(.success(cipherText))
            } catch {
                promise(.failure(error))
            }
        }
        .eraseToAnyPublisher()
    }

    /// Returns a publisher that decrypts a block of data using an ECC private key and the specified ECC algorithm.
    ///
    /// - Parameters:
    ///   - cipherText: The ciphertext data to decrypt.
    ///   - privateKey: ECC private key used for the decryption.
    ///   - algorithm: Algorithm used to perform the decryption. See ``EncryptionAlgorithm`` for more details.
    func decryptPublisher(
        for cipherText: some DataProtocol,
        withKey privateKey: some ECCPrivateKey & ConvertibleToSecKey,
        algorithm: EncryptionAlgorithm
    ) -> AnyPublisher<Data, Error> {
        Future { promise in
            do {
                let plainText = try Crypto.ECC.decrypt(cipherText, withKey: privateKey, algorithm: algorithm)
                promise(.success(plainText))
            } catch {
                promise(.failure(error))
            }
        }
        .eraseToAnyPublisher()
    }

    /// Returns a publisher that creates the cryptographic ECC signature for a block of data using a private key and specified algorithm.
    ///
    /// - Parameters:
    ///   - data: The data whose signature you want.
    ///   - privateKey: The ECC private key to use in creating the signature.
    ///   - algorithm: The ECC signing algorithm to use. See ``SignatureAlgorithm`` for more details.
    func signPublisher(
        for data: some DataProtocol,
        withKey privateKey: some ECCPrivateKey & ConvertibleToSecKey,
        algorithm: SignatureAlgorithm
    ) -> AnyPublisher<Data, Error> {
        Future { promise in
            do {
                let signature = try Crypto.ECC.sign(data, withKey: privateKey, algorithm: algorithm)
                promise(.success(signature))
            } catch {
                promise(.failure(error))
            }
        }
        .eraseToAnyPublisher()
    }

    /// Returns a publisher that creates the cryptographic ECC signature for a digest data using a private key and specified algorithm.
    ///
    /// - Parameters:
    ///   - digestData: The digest data whose signature you want.
    ///   - privateKey: The ECC private key to use in creating the signature.
    ///   - algorithm: The ECC signing algorithm to use. See ``SignatureAlgorithm`` for more details.
    func signDigestPublisher(
        for digestData: Data,
        withKey privateKey: some ECCPrivateKey & ConvertibleToSecKey,
        algorithm: SignatureAlgorithm
    ) -> AnyPublisher<Data, Error> {
        Future { promise in
            do {
                let signature = try Crypto.ECC.signDigest(digestData, withKey: privateKey, algorithm: algorithm)
                promise(.success(signature))
            } catch {
                promise(.failure(error))
            }
        }
        .eraseToAnyPublisher()
    }

    /// Returns a publisher that verifies the ECC cryptographic signature of a block of data using a public key and specified algorithm.
    ///
    /// - Parameters:
    ///   - signature: The signature that was created with a call to the `sign(_:withKey:algorithm:)` or `signDigest(_:withKey:algorithm:)` function.
    ///   - signedData: The data that was signed.
    ///   - publicKey: The ECC public key to use in evaluating the signature.
    ///   - algorithm: The algorithm that was used to create the signature. See ``SignatureAlgorithm`` for more details.
    func verifyPublisher(
        for signature: Data,
        of signedData: some DataProtocol,
        withKey publicKey: some ECCPublicKey & ConvertibleToSecKey,
        algorithm: SignatureAlgorithm
    ) -> AnyPublisher<Bool, Error> {
        Future { promise in
            do {
                let verified = try Crypto.ECC.verifySignature(signature, of: signedData, withKey: publicKey, algorithm: algorithm)
                promise(.success(verified))
            } catch {
                promise(.failure(error))
            }
        }
        .eraseToAnyPublisher()
    }
}
#endif

// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
#if canImport(Combine)
import Combine

public extension Crypto.AES {
    /// Creates IV data used for AES data encryption.
    ///
    /// - Returns: A publisher which publishes randomly generated IV data.
    static func createInitVectorPublisher() -> AnyPublisher<some SecureData, Error> {
        Future { promise in
            do {
                let initVectorData = try createInitVector()
                promise(.success(initVectorData))
            } catch {
                promise(.failure(error))
            }
        }
        .eraseToAnyPublisher()
    }

    /// Returns a publisher that encrypts a block of data using the Advanced Encryption Standard (AES).
    ///
    /// Cipher Block Chaining (CBC) is used for the encryption with PKCS#7 padding.
    ///
    /// - Parameters:
    ///   - plainText: The plaintext data to encrypt.
    ///   - key: The AES key used for the encryption.
    ///   - initVector: Initialization vector data used for the encryption.
    static func encryptPublisher(for plainText: Data, withKey key: some SecureData, initVector: some SecureData) -> AnyPublisher<Data, Error> {
        Future { promise in
            do {
                let cipherText = try encrypt(plainText, withKey: key, initVector: initVector)
                promise(.success(cipherText))
            } catch {
                promise(.failure(error))
            }
        }
        .eraseToAnyPublisher()
    }

    /// Returns a publisher that decrypts a block of data using the Advanced Encryption Standard (AES).
    ///
    /// Cipher Block Chaining (CBC) is used for the decryption with PKCS#7 padding.
    ///
    /// - Parameters:
    ///   - data: The PKCS#7 padded ciphertext data to decrypt.
    ///   - key: The AES key used for the decryption.
    ///   - initVector: Initialization vector data used for the decryption.
    static func decryptPublisher(for data: Data, withKey key: some SecureData, initVector: some SecureData) -> AnyPublisher<Data, Error> {
        Future { promise in
            do {
                let plainText = try decrypt(data, withKey: key, initVector: initVector)
                promise(.success(plainText))
            } catch {
                promise(.failure(error))
            }
        }
        .eraseToAnyPublisher()
    }
}
#endif

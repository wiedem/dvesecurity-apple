// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
#if canImport(Combine)
import Combine

@available(iOS 13, *)
public extension Crypto.AES {
    /// Creates IV data used for AES data encryption.
    ///
    /// - Returns: A publisher which publishes randomly generated IV data.
    static func createIVPublisher() -> AnyPublisher<Data, Error> {
        Future { promise in
            do {
                let ivData = try createIV()
                promise(.success(ivData))
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
    ///   - ivData: IV data used for the encryption.
    static func encryptPublisher(for plainText: Data, withKey key: Key, ivData: Data) -> AnyPublisher<Data, Error> {
        Future { promise in
            do {
                let cipherText = try encrypt(plainText, withKey: key, ivData: ivData)
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
    ///   - ivData: IV data used for the decryption.
    static func decryptPublisher(for data: Data, withKey key: Key, ivData: Data) -> AnyPublisher<Data, Error> {
        Future { promise in
            do {
                let plainText = try decrypt(data, withKey: key, ivData: ivData)
                promise(.success(plainText))
            } catch {
                promise(.failure(error))
            }
        }
        .eraseToAnyPublisher()
    }
}
#endif

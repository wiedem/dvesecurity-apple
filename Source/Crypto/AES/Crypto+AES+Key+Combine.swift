// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
#if canImport(Combine)
import Combine

public extension Crypto.AES.Key {
    /// Returns a publisher that encrypts a block of data using the Advanced Encryption Standard (AES).
    ///
    /// Cipher Block Chaining (CBC) is used for the encryption with PKCS#7 padding.
    ///
    /// - Parameters:
    ///   - plainText: The plaintext data to encrypt.
    ///   - initVector: Initialization vector data used for the encryption.
    func encryptPublisher(for plainText: Data, initVector: some SecureData) -> AnyPublisher<Data, Error> {
        Crypto.AES.encryptPublisher(for: plainText, withKey: keyData, initVector: initVector)
    }

    /// Returns a publisher that decrypts a block of data using the Advanced Encryption Standard (AES).
    ///
    /// Cipher Block Chaining (CBC) is used for the decryption with PKCS#7 padding.
    ///
    /// - Parameters:
    ///   - data: The PKCS#7 padded ciphertext data to decrypt.
    ///   - initVector: Initialization vector data used for the decryption.
    func decryptPublisher(for data: Data, initVector: some SecureData) -> AnyPublisher<Data, Error> {
        Crypto.AES.decryptPublisher(for: data, withKey: keyData, initVector: initVector)
    }
}
#endif

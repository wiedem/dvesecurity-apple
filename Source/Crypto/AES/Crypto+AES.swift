// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import CommonCrypto
import Foundation

public extension Crypto {
    /// A container for Advanced Encryption Standard (AES) types and operations.
    enum AES {
        /// AES block size used for all AES operations.
        public static var blockSize: Int { return kCCBlockSizeAES128 }

        /// Creates IV data used for AES data encryption.
        ///
        /// - Returns: Randomly generated IV data.
        public static func createIV() throws -> Data {
            try Crypto.createRandomData(length: blockSize)
        }

        /// Encrypts a block of data using the Advanced Encryption Standard (AES).
        ///
        /// Cipher Block Chaining (CBC) is used for the encryption with PKCS#7 padding.
        ///
        /// - Parameters:
        ///   - plainText: The plaintext data to encrypt.
        ///   - key: The AES key used for the encryption.
        ///   - ivData: IV data used for the encryption.
        ///
        /// - Returns: The ciphertext data with PKCS#7 padding represented as a Data object.
        public static func encrypt<PD>(_ plainText: PD, withKey key: Key, ivData: Data) throws -> Data where PD: ContiguousBytes {
            try cryptOperation(CCOperation(kCCEncrypt),
                               algorithm: CCAlgorithm(kCCAlgorithmAES),
                               options: CCOptions(kCCOptionPKCS7Padding),
                               for: plainText,
                               withKey: key.rawKeyRepresentation,
                               iv: ivData)
        }

        /// Decrypts a block of data using the Advanced Encryption Standard (AES).
        ///
        /// Cipher Block Chaining (CBC) is used for the decryption with PKCS#7 padding.
        ///
        /// - Parameters:
        ///   - data: The PKCS#7 padded ciphertext data to decrypt.
        ///   - key: The AES key used for the decryption.
        ///   - ivData: IV data used for the decryption.
        ///
        /// - Returns: The decrypted plaintext data.
        public static func decrypt<D>(_ data: D, withKey key: Key, ivData: Data) throws -> Data where D: ContiguousBytes {
            try cryptOperation(CCOperation(kCCDecrypt),
                               algorithm: CCAlgorithm(kCCAlgorithmAES),
                               options: CCOptions(kCCOptionPKCS7Padding),
                               for: data,
                               withKey: key.rawKeyRepresentation,
                               iv: ivData)
        }
    }
}

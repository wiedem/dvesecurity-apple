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
        /// The generated initialization vector can be used for AES encryption methods, such as ``Key/encrypt(_:initVector:)``.
        ///
        /// - Important: Initialization vectors don't need to be kept secret but should not be re-used for the same AES key.
        /// IV data should also be protected against manipulation.
        ///
        /// - Returns: Randomly generated initialization vector data.
        public static func createInitVector() throws -> some SecureData {
            try Crypto.KeyData.createRandomData(length: blockSize)
        }

        /// Encrypts a block of data using the Advanced Encryption Standard (AES).
        ///
        /// Cipher Block Chaining (CBC) is used for the encryption with PKCS#7 padding.
        ///
        /// - Parameters:
        ///   - plainText: The plaintext data to encrypt.
        ///   - key: The AES key used for the encryption.
        ///   - initVector: Initialization vector data used for the encryption. See ``createInitVector()``,
        ///
        /// - Returns: The ciphertext data with PKCS#7 padding represented as a Data object.
        public static func encrypt(
            _ plainText: some ContiguousBytes,
            withKey key: some SecureData,
            initVector: some SecureData
        ) throws -> Data {
            try cryptOperation(
                CCOperation(kCCEncrypt),
                algorithm: CCAlgorithm(kCCAlgorithmAES),
                options: CCOptions(kCCOptionPKCS7Padding),
                for: plainText,
                withKey: key,
                initVector: initVector
            )
        }

        /// Decrypts a block of data using the Advanced Encryption Standard (AES).
        ///
        /// Cipher Block Chaining (CBC) is used for the decryption with PKCS#7 padding.
        ///
        /// - Parameters:
        ///   - data: The PKCS#7 padded ciphertext data to decrypt.
        ///   - key: The AES key used for the decryption.
        ///   - initVector: Initialization vector data used for the decryption.
        ///
        /// - Returns: The decrypted plaintext data.
        public static func decrypt(
            _ data: some ContiguousBytes,
            withKey key: some SecureData,
            initVector: some SecureData
        ) throws -> Data {
            try cryptOperation(
                CCOperation(kCCDecrypt),
                algorithm: CCAlgorithm(kCCAlgorithmAES),
                options: CCOptions(kCCOptionPKCS7Padding),
                for: data,
                withKey: key,
                initVector: initVector
            )
        }
    }
}

public extension Crypto.AES {
    /// Encrypts a block of data using the Advanced Encryption Standard (AES).
    ///
    /// Cipher Block Chaining (CBC) is used for the encryption with PKCS#7 padding.
    ///
    /// - Parameters:
    ///   - plainText: The plaintext data to encrypt.
    ///   - key: The AES key used for the encryption.
    ///   - initVector: Initialization vector data used for the encryption.  See ``createInitVector()``,
    ///
    /// - Returns: The ciphertext data with PKCS#7 padding represented as a Data object.
    static func encrypt(
        _ plainText: some ContiguousBytes,
        withKey key: some KeyDataRepresentable,
        initVector: some SecureData
    ) throws -> Data {
        try encrypt(plainText, withKey: key.keyData, initVector: initVector)
    }

    /// Decrypts a block of data using the Advanced Encryption Standard (AES).
    ///
    /// Cipher Block Chaining (CBC) is used for the decryption with PKCS#7 padding.
    ///
    /// - Parameters:
    ///   - data: The PKCS#7 padded ciphertext data to decrypt.
    ///   - key: The AES key used for the decryption.
    ///   - initVector: Initialization vector data used for the decryption.
    ///
    /// - Returns: The decrypted plaintext data.
    static func decrypt(
        _ data: some ContiguousBytes,
        withKey key: some KeyDataRepresentable,
        initVector: some SecureData
    ) throws -> Data {
        try decrypt(data, withKey: key.keyData, initVector: initVector)
    }
}

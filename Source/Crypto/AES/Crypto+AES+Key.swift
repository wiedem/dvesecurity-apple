// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import CommonCrypto
import Foundation

public extension Crypto.AES {
    /// A symmetric cryptographic key for AES operations.
    ///
    /// The storate for the key data must implement the ``SecureData`` protocol, which ensures that the key data is deleted from the memory as soon as it is
    /// no longer required.
    ///
    /// `Key` itself implements the ``SecureData`` protocol by acting as a facade to the underlying key data.
    struct Key<SD: SecureData> {
        /// The data of the key.
        public let keyData: SD

        /// Creates a new AES key.
        ///
        /// - Parameter keyData: An instance of type ``SecureData`` containing the data of the key.
        public init(keyData: SD) {
            self.keyData = keyData
        }
    }
}

extension Crypto.AES.Key: Equatable where SD == Crypto.KeyData {}
extension Crypto.AES.Key: Hashable where SD == Crypto.KeyData {}
extension Crypto.AES.Key: KeyDataRepresentable where SD == Crypto.KeyData {}

public extension Crypto.AES.Key {
    /// Encrypts a block of data using the Advanced Encryption Standard (AES).
    ///
    /// Cipher Block Chaining (CBC) is used for the encryption with PKCS#7 padding.
    ///
    /// - Parameters:
    ///   - plainText: The plaintext data to encrypt.
    ///   - initVector: Initialization vector data used for the encryption.  See ``Crypto/AES/createInitVector()``,
    ///
    /// - Returns: The ciphertext represented as a Data object.
    func encrypt(_ plainText: some ContiguousBytes, initVector: some SecureData) throws -> Data {
        try Crypto.AES.encrypt(plainText, withKey: keyData, initVector: initVector)
    }

    /// Decrypts a block of data using the Advanced Encryption Standard (AES).
    ///
    /// Cipher Block Chaining (CBC) is used for the decryption with PKCS#7 padding.
    ///
    /// - Parameters:
    ///   - data: The ciphertext data to decrypt.
    ///   - initVector: Initialization vector data used for the decryption.
    ///
    /// - Returns: The decrypted plaintext data.
    func decrypt(_ data: some ContiguousBytes, initVector: some SecureData) throws -> Data {
        try Crypto.AES.decrypt(data, withKey: keyData, initVector: initVector)
    }
}

// MARK: - AES key derivation.
public extension Crypto.AES.Key where SD == Crypto.KeyData {
    /// The sizes that a AES cryptographic key can take.
    struct KeySize {
        /// 128 bit AES key size.
        static let bits128 = Self(sizeInBytes: kCCKeySizeAES128)
        /// 192 bit AES key size.
        static let bits192 = Self(sizeInBytes: kCCKeySizeAES192)
        /// 256 bit AES key size.
        static let bits256 = Self(sizeInBytes: kCCKeySizeAES256)

        /// The size of the key in bytes.
        private(set) var sizeInBytes: Int

        /// Creates a new key size of the given length in bytes.
        public init(sizeInBytes: Int) {
            self.sizeInBytes = sizeInBytes
        }

        /// Creates a new key size of the given length in bits.
        public init(bitCount: Int) {
            self.init(sizeInBytes: bitCount * 8)
        }
    }

    /// Pseudo Random Algorithm used for key derivations.
    enum PseudoRandomAlgorithm {
        case hmacAlgSHA1
        case hmacAlgSHA224
        case hmacAlgSHA256
        case hmacAlgSHA384
        case hmacAlgSHA512
    }

    /// Creates a new random symmetric AES key.
    ///
    /// - Parameter keySize: The expected size of the key.
    static func createRandom(_ keySize: KeySize) throws -> Self {
        let keyData = try Crypto.KeyData.createRandomData(length: keySize.sizeInBytes)
        return Self(keyData: keyData)
    }

    /// Derive a symmetric encryption key from a text password or passphrase.
    ///
    /// - Parameters:
    ///   - keySize: The expected size of the derived key.
    ///   - password: The text password used as input to the derivation function. The actual octets present in this string will be used with no additional processing.
    ///   - salt: The salt used as input to the derivation function.
    ///   - pseudoRandomAlgorithm: The Pseudo Random Algorithm to use for the derivation iterations.
    ///   - rounds: The number of rounds of the Pseudo Random Algorithm to use.
    init(
        keySize: KeySize,
        password: String,
        withSalt salt: String,
        pseudoRandomAlgorithm: PseudoRandomAlgorithm,
        rounds: UInt32
    ) throws {
        guard let passwordData = password.data(using: .utf8) else {
            throw Crypto.AESError.invalidPassword
        }
        guard let saltData = salt.data(using: .utf8) else {
            throw Crypto.AESError.invalidSalt
        }
        let derivedKeyLength = keySize.sizeInBytes

        let keyData = try Crypto.KeyData(byteCount: derivedKeyLength) { rawBufferPointer in
            let result = passwordData.withUnsafeBytes { passwordBuffer in
                saltData.withUnsafeBytes { saltBuffer in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBuffer.bindMemory(to: Int8.self).baseAddress!,
                        passwordBuffer.count,
                        saltBuffer.bindMemory(to: UInt8.self).baseAddress!,
                        saltBuffer.count,
                        pseudoRandomAlgorithm.ccryptoValue,
                        rounds,
                        rawBufferPointer.bindMemory(to: UInt8.self).baseAddress!,
                        derivedKeyLength
                    )
                }
            }

            guard result == kCCSuccess else {
                throw CommonCryptoError(status: result)
            }
        }

        self.init(keyData: keyData)
    }
}

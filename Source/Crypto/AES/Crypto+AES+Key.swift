// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import CommonCrypto
import Foundation

/// A type for a symmetic cryptographic key.
public protocol SymmetricKey: ContiguousBytes {
    /// The number of bits in the key.
    var bitCount: Int { get }
}

public extension Crypto.AES {
    /// The sizes that a AES cryptographic key can take.
    struct KeySize {
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

    /// A symmetric cryptographic key for AES.
    struct Key: SymmetricKey {
        public let blockSize: Int = kCCBlockSizeAES128
        public var bitCount: Int { keyData.count * 8 }

        private let keyData: Data

        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try keyData.withUnsafeBytes(body)
        }
    }
}

public extension Crypto.AES.Key {
    /// Encrypts a block of data using the Advanced Encryption Standard (AES).
    ///
    /// Cipher Block Chaining (CBC) is used for the encryption with PKCS#7 padding.
    ///
    /// - Parameters:
    ///   - plainText: The plaintext data to encrypt.
    ///   - ivData: IV data used for the encryption.
    ///
    /// - Returns: The ciphertext represented as a Data object.
    func encrypt(_ plainText: Data, ivData: Data) throws -> Data {
        try Crypto.AES.encrypt(plainText, withKey: self, ivData: ivData)
    }

    /// Decrypts a block of data using the Advanced Encryption Standard (AES).
    ///
    /// Cipher Block Chaining (CBC) is used for the decryption with PKCS#7 padding.
    ///
    /// - Parameters:
    ///   - data: The ciphertext data to decrypt.
    ///   - ivData: IV data used for the decryption.
    ///
    /// - Returns: The decrypted plaintext data.
    func decrypt(_ data: Data, ivData: Data) throws -> Data {
        try Crypto.AES.decrypt(data, withKey: self, ivData: ivData)
    }
}

// MARK: - RawKeyConvertible
extension Crypto.AES.Key: RawKeyConvertible {
    /// Raw data representation of the AES key.
    public var rawKeyRepresentation: Data { keyData }

    /// Create a new AES key from raw data.
    ///
    /// - Parameter rawKeyRepresentation: The raw key data from which the key should be created.
    public init(rawKeyRepresentation: some ContiguousBytes) {
        keyData = rawKeyRepresentation.withUnsafeBytes { Data($0) }
    }
}

// MARK: - Equatable
extension Crypto.AES.Key: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.rawKeyRepresentation == rhs.rawKeyRepresentation
    }
}

// MARK: - AESKeySize default values
public extension Crypto.AES.KeySize {
    /// 128 bit AES key size.
    static let bits128 = Self(sizeInBytes: kCCKeySizeAES128)
    /// 192 bit AES key size.
    static let bits192 = Self(sizeInBytes: kCCKeySizeAES192)
    /// 256 bit AES key size.
    static let bits256 = Self(sizeInBytes: kCCKeySizeAES256)
}

// MARK: - AES key derivation.
public extension Crypto.AES.Key {
    /// Pseudo Random Algorithm used for key derivations.
    enum PseudoRandomAlgorithm {
        case hmacAlgSHA1
        case hmacAlgSHA224
        case hmacAlgSHA256
        case hmacAlgSHA384
        case hmacAlgSHA512
    }

    /// Derive a symmetric encryption key from a text password or passphrase.
    ///
    /// - Parameters:
    ///   - keySize: The expected size of the derived key.
    ///   - password: The text password used as input to the derivation function. The actual octets present in this string will be used with no additional processing.
    ///   - salt: The salt used as input to the derivation function.
    ///   - pseudoRandomAlgorithm: The Pseudo Random Algorithm to use for the derivation iterations.
    ///   - rounds: The number of rounds of the Pseudo Random Algorithm to use.
    init(keySize: Crypto.AES.KeySize, password: String, withSalt salt: String, pseudoRandomAlgorithm: PseudoRandomAlgorithm, rounds: UInt32) throws {
        guard let passwordData = password.data(using: .utf8) else {
            throw Crypto.AESError.invalidPassword
        }
        guard let saltData = salt.data(using: .utf8) else {
            throw Crypto.AESError.invalidSalt
        }
        let derivedKeyLength = keySize.sizeInBytes
        var derivedKey = Data(count: derivedKeyLength)

        let result = derivedKey.withUnsafeMutableBytes { derivedKeyBuffer in
            passwordData.withUnsafeBytes { passwordBuffer in
                saltData.withUnsafeBytes { saltBuffer in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBuffer.bindMemory(to: Int8.self).baseAddress!,
                        passwordBuffer.count,
                        saltBuffer.bindMemory(to: UInt8.self).baseAddress!,
                        saltBuffer.count,
                        pseudoRandomAlgorithm.ccryptoValue,
                        rounds,
                        derivedKeyBuffer.bindMemory(to: UInt8.self).baseAddress!,
                        derivedKeyLength
                    )
                }
            }
        }

        guard result == kCCSuccess else {
            throw CommonCryptoError(status: result)
        }

        self.init(keyData: derivedKey)
    }
}

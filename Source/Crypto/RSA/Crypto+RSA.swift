// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

public extension Crypto {
    /// A container for RSA types and operations.
    enum RSA {
        /// RSA encryption and decryption algorithms available for the RSA class.
        public enum EncryptionAlgorithm: CaseIterable {
            /// Raw RSA encryption or decryption.
            ///
            /// - Warning: Note that direct use of this algorithm without padding is cryptographically very weak, it is important to always introduce some kind of padding.
            /// - Attention: Input data size for the encryption is limited to the size returned by the ``RSAKey/maxPlainTextLength(for:)-2z0eu`` function.
            case raw
            /// RSA encryption or decryption with data padded using PKCS#1 padding scheme.
            ///
            /// This algorithm should be used only for backward compatibility with existing protocols and data. New implementations should choose cryptographically stronger algorithm instead.
            ///
            /// - Attention: Input data size for the encryption is limited to the size returned by the ``RSAKey/maxPlainTextLength(for:)-2z0eu`` function.
            case PKCS1
            /// RSA encryption or decryption with data padded using OAEP padding scheme.
            ///
            /// SHA1 is used internally.  Use ``OAEPSHA1AESGCM`` to be able to encrypt and decrypt arbitrary long data.
            ///
            /// - Attention: Input data size for the encryption is limited to the size returned by the ``RSAKey/maxPlainTextLength(for:)-2z0eu`` function.
            case OAEPSHA1
            /// RSA encryption or decryption with data padded using OAEP padding scheme.
            ///
            /// SHA224 is used internally. Use ``OAEPSHA224AESGCM`` to be able to encrypt and decrypt arbitrary long data.
            ///
            /// - Attention: Input data size for the encryption is limited to the size returned by the ``RSAKey/maxPlainTextLength(for:)-2z0eu`` function.
            case OAEPSHA224
            /// RSA encryption or decryption with data padded using OAEP padding scheme.
            ///
            /// SHA256 is used internally. Use ``OAEPSHA256AESGCM`` to be able to encrypt and decrypt arbitrary long data.
            ///
            /// - Attention: Input data size for the encryption is limited to the size returned by the ``RSAKey/maxPlainTextLength(for:)-2z0eu`` function.
            case OAEPSHA256
            /// RSA encryption or decryption with data padded using OAEP padding scheme.
            ///
            /// SHA384 is used internally. Use ``OAEPSHA384AESGCM`` to be able to encrypt and decrypt arbitrary long data.
            ///
            /// - Attention: Input data size for the encryption is limited to the size returned by the ``RSAKey/maxPlainTextLength(for:)-2z0eu`` function.
            case OAEPSHA384
            /// RSA encryption or decryption with data padded using OAEP padding scheme.
            ///
            /// SHA512 is used internally. Use ``OAEPSHA512AESGCM`` to be able to encrypt and decrypt arbitrary long data.
            ///
            /// - Attention: Input data size for the encryption is limited to the size returned by the ``RSAKey/maxPlainTextLength(for:)-2z0eu`` function.
            case OAEPSHA512
            /// Hybrid encryption and decryption for arbitrary long data using an RSA encrypted AES session key.
            ///
            /// Randomly generated AES session key is encrypted by RSA with OAEP padding. User data are encrypted using session key in GCM mode with all-zero 16 bytes long IV (initialization vector).
            ///
            /// Finally 16 byte AES-GCM tag is appended to ciphertext.
            ///
            /// 256bit AES key is used if RSA key is 4096bit or bigger, otherwise 128bit AES key is used.
            /// Raw public key data is used as authentication data for AES-GCM encryption.
            ///
            /// SHA1 is used internally.
            case OAEPSHA1AESGCM
            /// Hybrid encryption and decryption for arbitrary long data using an RSA encrypted AES session key.

            /// Randomly generated AES session key is encrypted by RSA with OAEP padding. User data are encrypted using session key in GCM mode with all-zero 16 bytes long IV (initialization vector).
            ///
            /// Finally 16 byte AES-GCM tag is appended to ciphertext.
            ///
            /// 256bit AES key is used if RSA key is 4096bit or bigger, otherwise 128bit AES key is used.
            /// Raw public key data is used as authentication data for AES-GCM encryption.
            ///
            /// SHA224 is used internally.
            case OAEPSHA224AESGCM
            /// Hybrid encryption and decryption for arbitrary long data using an RSA encrypted AES session key.
            ///
            /// Randomly generated AES session key is encrypted by RSA with OAEP padding. User data are encrypted using session key in GCM mode with all-zero 16 bytes long IV (initialization vector).
            ///
            /// Finally 16 byte AES-GCM tag is appended to ciphertext.
            ///
            /// 256bit AES key is used if RSA key is 4096bit or bigger, otherwise 128bit AES key is used.
            /// Raw public key data is used as authentication data for AES-GCM encryption.
            ///
            /// SHA256 is used internally.
            case OAEPSHA256AESGCM
            /// Hybrid encryption and decryption for arbitrary long data using an RSA encrypted AES session key.
            ///
            /// Randomly generated AES session key is encrypted by RSA with OAEP padding. User data are encrypted using session key in GCM mode with all-zero 16 bytes long IV (initialization vector).
            ///
            /// Finally 16 byte AES-GCM tag is appended to ciphertext.
            ///
            /// 256bit AES key is used if RSA key is 4096bit or bigger, otherwise 128bit AES key is used.
            /// Raw public key data is used as authentication data for AES-GCM encryption.
            ///
            /// SHA384 is used internally.
            case OAEPSHA384AESGCM
            /// Hybrid encryption and decryption for arbitrary long data using an RSA encrypted AES session key.
            ///
            /// Randomly generated AES session key is encrypted by RSA with OAEP padding. User data are encrypted using session key in GCM mode with all-zero 16 bytes long IV (initialization vector).
            ///
            /// Finally 16 byte AES-GCM tag is appended to ciphertext.
            ///
            /// 256bit AES key is used if RSA key is 4096bit or bigger, otherwise 128bit AES key is used.
            /// Raw public key data is used as authentication data for AES-GCM encryption.
            ///
            /// SHA512 is used internally.
            case OAEPSHA512AESGCM
        }

        /// RSA signature algorithms available for the RSA class.
        public enum SignatureAlgorithm: CaseIterable {
            /// RSA signature with PKCS#1 padding.
            ///
            /// When used to sign a message, SHA-1 digest is generated from input data of any size.
            /// When used to sign a digest, input data must be SHA-1 generated digest
            case PKCS1v15SHA1
            /// RSA signature with PKCS#1 padding.
            ///
            /// When used to sign a message, SHA-224 digest is generated from input data of any size.
            /// When used to sign a digest, input data must be SHA-224 generated digest
            case PKCS1v15SHA224
            /// RSA signature with PKCS#1 padding.
            ///
            /// When used to sign a message, SHA-256 digest is generated from input data of any size.
            /// When used to sign a digest, input data must be SHA-256 generated digest
            case PKCS1v15SHA256
            /// RSA signature with PKCS#1 padding.
            ///
            /// When used to sign a message, SHA-384 digest is generated from input data of any size.
            /// When used to sign a digest, input data must be SHA-384 generated digest
            case PKCS1v15SHA384
            /// RSA signature with PKCS#1 padding.
            ///
            /// When used to sign a message, SHA-512 digest is generated from input data of any size.
            /// When used to sign a digest, input data must be SHA-512 generated digest
            case PKCS1v15SHA512
            /// RSA signature with RSASSA-PSS padding according to PKCS#1 v2.1.
            ///
            /// PSS padding is calculated using MGF1 with SHA1 and saltLength parameter is set to 20 (SHA-1 output size).
            ///
            /// When used to sign a message, SHA-1 digest is generated from input data of any size.
            /// When used to sign a digest, input data must be SHA-1 generated digest
            case PSSSHA1
            /// RSA signature with RSASSA-PSS padding according to PKCS#1 v2.1.
            ///
            /// PSS padding is calculated using MGF1 with SHA224 and saltLength parameter is set to 28 (SHA-1 output size).
            ///
            /// When used to sign a message, SHA-224 digest is generated from input data of any size.
            /// When used to sign a digest, input data must be SHA-224 generated digest
            case PSSSHA224
            /// RSA signature with RSASSA-PSS padding according to PKCS#1 v2.1.
            ///
            /// PSS padding is calculated using MGF1 with SHA256 and saltLength parameter is set to 32 (SHA-1 output size).
            ///
            /// When used to sign a message, SHA-256 digest is generated from input data of any size.
            /// When used to sign a digest, input data must be SHA-256 generated digest
            ///
            /// - Note: RSA keys must have at least a size of 528 bits for this algorithm.
            case PSSSHA256
            /// RSA signature with RSASSA-PSS padding according to PKCS#1 v2.1.
            ///
            /// PSS padding is calculated using MGF1 with SHA384 and saltLength parameter is set to 48 (SHA-1 output size).
            ///
            /// When used to sign a message, SHA-384 digest is generated from input data of any size.
            /// When used to sign a digest, input data must be SHA-384 generated digest
            ///
            /// - Note: RSA keys must have at least a size of 784 bits for this algorithm.
            case PSSSHA384
            /// RSA signature with RSASSA-PSS padding according to PKCS#1 v2.1.
            ///
            /// PSS padding is calculated using MGF1 with SHA512 and saltLength parameter is set to 64 (SHA-1 output size).
            ///
            /// When used to sign a message, SHA-512 digest is generated from input data of any size.
            /// When used to sign a digest, input data must be SHA-512 generated digest
            ///
            /// - Note: RSA keys must have at least a size of 1040 bits for this algorithm.
            case PSSSHA512
        }
    }
}

public extension Crypto.RSA.EncryptionAlgorithm {
    /// Returns the maximum plaintext length in bytes for an RSA key.
    ///
    /// - Parameter rsaKey: The RSA key for which the maximum length should be returned.
    ///
    /// - Returns: the maximum plaintext length in bytes for the RSA key.
    func maxPlainTextLength(for rsaKey: RSAKey) -> Int? {
        return rsaKey.maxPlainTextLength(for: self)
    }
}

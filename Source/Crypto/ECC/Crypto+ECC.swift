// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

public extension Crypto {
    /// A container for Elliptic Curve Cryptography (ECC) types and operations.
    enum ECC {
        /// Elliptic Curve Encryption Standard X963 encryption and decryption algorithms available for the ECC class.
        public enum EncryptionAlgorithm: CaseIterable {
            /// Hybrid ECIES encryption or decryption algorithm.
            ///
            /// Encryption is done using AES-GCM with key negotiated by ``Crypto/ECC/KeyExchangeAlgorithm/ECDHStandardX963SHA224``.
            /// AES Key size is 128bit for EC keys `<=`256bit and 256bit for bigger EC keys.
            /// Ephemeral public key data is used as sharedInfo for KDF.
            ///
            /// AES-GCM uses 16 bytes long TAG, AES key is first half of KDF output and 16 byte long IV (initialization vector) is second half of KDF output.
            ///
            /// - Note: This algorithm does not limit the size of the message to be encrypted or decrypted.
            case ECIESStandardVariableIVX963SHA224AESGCM
            /// Hybrid ECIES encryption or decryption algorithm.
            ///
            /// Encryption is done using AES-GCM with key negotiated by ``Crypto/ECC/KeyExchangeAlgorithm/ECDHStandardX963SHA256``.
            /// AES Key size is 128bit for EC keys `<=`256bit and 256bit for bigger EC keys.
            /// Ephemeral public key data is used as sharedInfo for KDF.
            ///
            /// AES-GCM uses 16 bytes long TAG, AES key is first half of KDF output and 16 byte long IV (initialization vector) is second half of KDF output.
            ///
            /// - Note: This algorithm does not limit the size of the message to be encrypted or decrypted.
            case ECIESStandardVariableIVX963SHA256AESGCM
            /// Hybrid ECIES encryption or decryption algorithm.
            ///
            /// Encryption is done using AES-GCM with key negotiated by ``Crypto/ECC/KeyExchangeAlgorithm/ECDHStandardX963SHA384``.
            /// AES Key size is 128bit for EC keys `<=`256bit and 256bit for bigger EC keys. Ephemeral public key data is used as sharedInfo for KDF.
            ///
            /// AES-GCM uses 16 bytes long TAG, AES key is first half of KDF output and 16 byte long IV (initialization vector) is second half of KDF output.
            ///
            /// - Note: This algorithm does not limit the size of the message to be encrypted or decrypted.
            case ECIESStandardVariableIVX963SHA384AESGCM
            /// Hybrid ECIES encryption or decryption algorithm.
            ///
            /// Encryption is done using AES-GCM with key negotiated by ``Crypto/ECC/KeyExchangeAlgorithm/ECDHStandardX963SHA512``.
            /// AES Key size is 128bit for EC keys `<=`256bit and 256bit for bigger EC keys.
            /// Ephemeral public key data is used as sharedInfo for KDF.
            ///
            /// AES-GCM uses 16 bytes long TAG, AES key is first half of KDF output and 16 byte long IV (initialization vector) is second half of KDF output.
            ///
            /// - Note: This algorithm does not limit the size of the message to be encrypted or decrypted.
            case ECIESStandardVariableIVX963SHA512AESGCM
            /// Hybrid ECIES encryption or decryption algorithm.
            ///
            /// Encryption is done using AES-GCM with key negotiated by ``Crypto/ECC/KeyExchangeAlgorithm/ECDHCofactorX963SHA224``.
            /// AES Key size is 128bit for EC keys `<=`256bit and 256bit for bigger EC keys. Ephemeral public key data is used as sharedInfo for KDF.
            ///
            /// AES-GCM uses 16 bytes long TAG, AES key is first half of KDF output and 16 byte long IV (initialization vector) is second half of KDF output.
            ///
            /// - Note: This algorithm does not limit the size of the message to be encrypted or decrypted.
            case ECIESCofactorVariableIVX963SHA224AESGCM
            /// Hybrid ECIES encryption or decryption algorithm.
            ///
            /// Encryption is done using AES-GCM with key negotiated by ``Crypto/ECC/KeyExchangeAlgorithm/ECDHCofactorX963SHA256``.
            /// AES Key size is 128bit for EC keys `<=`256bit and 256bit for bigger EC keys. Ephemeral public key data is used as sharedInfo for KDF.
            ///
            /// AES-GCM uses 16 bytes long TAG, AES key is first half of KDF output and 16 byte long IV (initialization vector) is second half of KDF output.
            ///
            /// - Note: This algorithm does not limit the size of the message to be encrypted or decrypted.
            case ECIESCofactorVariableIVX963SHA256AESGCM
            /// Hybrid ECIES encryption or decryption algorithm.
            ///
            /// Encryption is done using AES-GCM with key negotiated by ``Crypto/ECC/KeyExchangeAlgorithm/ECDHCofactorX963SHA384``.
            /// AES Key size is 128bit for EC keys `<=`256bit and 256bit for bigger EC keys. Ephemeral public key data is used as sharedInfo for KDF.
            ///
            /// AES-GCM uses 16 bytes long TAG, AES key is first half of KDF output and 16 byte long IV (initialization vector) is second half of KDF output.
            ///
            /// - Note: This algorithm does not limit the size of the message to be encrypted or decrypted.
            case ECIESCofactorVariableIVX963SHA384AESGCM
            /// Hybrid ECIES encryption or decryption algorithm.
            ///
            /// Encryption is done using AES-GCM with key negotiated by ``Crypto/ECC/KeyExchangeAlgorithm/ECDHCofactorX963SHA512``.
            /// AES Key size is 128bit for EC keys `<=`256bit and 256bit for bigger EC keys. Ephemeral public key data is used as sharedInfo for KDF.
            ///
            /// AES-GCM uses 16 bytes long TAG, AES key is first half of KDF output and 16 byte long IV (initialization vector) is second half of KDF output.
            ///
            /// - Note: This algorithm does not limit the size of the message to be encrypted or decrypted.
            case ECIESCofactorVariableIVX963SHA512AESGCM
        }

        /// Elliptic Curve Signature Message X962 algorithms.
        public enum SignatureAlgorithm: CaseIterable {
            /// ECDSA algorithm, signature is in DER x9.62 encoding, SHA-1 digest is generated from input data of any size.
            case ECDSAX962SHA1
            /// ECDSA algorithm, signature is in DER x9.62 encoding, SHA-224 digest is generated from input data of any size.
            case ECDSAX962SHA224
            /// ECDSA algorithm, signature is in DER x9.62 encoding, SHA-256 digest is generated from input data of any size.
            case ECDSAX962SHA256
            /// ECDSA algorithm, signature is in DER x9.62 encoding, SHA-384 digest is generated from input data of any size.
            case ECDSAX962SHA384
            /// ECDSA algorithm, signature is in DER x9.62 encoding, SHA-512 digest is generated from input data of any size.
            case ECDSAX962SHA512
        }

        /// Elliptic Curve Key Exchange algorithms.
        public enum KeyExchangeAlgorithm: CaseIterable {
            /// Compute shared secret using ECDH cofactor algorithm.
            ///
            /// This algorithm does not accept any parameters, length of output raw shared secret is given by the length of the key.
            case ECDHCofactor
            /// Compute shared secret using ECDH cofactor algorithm.
            ///
            /// Applies ANSI X9.63 KDF with SHA1 as hashing function.
            /// Requires `kSecKeyKeyExchangeParameterRequestedSize` and allows `kSecKeyKeyExchangeParameterSharedInfo` parameters to be used.
            case ECDHCofactorX963SHA1
            /// Compute shared secret using ECDH cofactor algorithm.
            ///
            /// Applies ANSI X9.63 KDF with SHA224 as hashing function.
            /// Requires `kSecKeyKeyExchangeParameterRequestedSize` and allows `kSecKeyKeyExchangeParameterSharedInfo` parameters to be used.
            case ECDHCofactorX963SHA224
            /// Compute shared secret using ECDH cofactor algorithm.
            ///
            /// Applies ANSI X9.63 KDF with SHA256 as hashing function.
            /// Requires `kSecKeyKeyExchangeParameterRequestedSize` and allows `kSecKeyKeyExchangeParameterSharedInfo` parameters to be used.
            case ECDHCofactorX963SHA256
            /// Compute shared secret using ECDH cofactor algorithm.
            ///
            /// Applies ANSI X9.63 KDF with SHA384 as hashing function.
            /// Requires `kSecKeyKeyExchangeParameterRequestedSize` and allows `kSecKeyKeyExchangeParameterSharedInfo` parameters to be used.
            case ECDHCofactorX963SHA384
            /// Compute shared secret using ECDH cofactor algorithm.
            ///
            /// Applies ANSI X9.63 KDF with SHA512 as hashing function.
            /// Requires `kSecKeyKeyExchangeParameterRequestedSize` and allows `kSecKeyKeyExchangeParameterSharedInfo` parameters to be used.
            case ECDHCofactorX963SHA512
            /// Compute shared secret using ECDH algorithm without cofactor.
            ///
            /// This algorithm does not accept any parameters, length of output raw shared secret is given by the length of the key.
            case ECDHStandard
            /// Compute shared secret using ECDH algorithm without cofactor
            ///
            /// Applies ANSI X9.63 KDF with SHA1 as hashing function.
            /// Requires `kSecKeyKeyExchangeParameterRequestedSize` and allows `kSecKeyKeyExchangeParameterSharedInfo` parameters to be used.
            case ECDHStandardX963SHA1
            /// Compute shared secret using ECDH algorithm without cofactor
            ///
            /// Applies ANSI X9.63 KDF with SHA224 as hashing function.
            /// Requires `kSecKeyKeyExchangeParameterRequestedSize` and allows `kSecKeyKeyExchangeParameterSharedInfo` parameters to be used.
            case ECDHStandardX963SHA224
            /// Compute shared secret using ECDH algorithm without cofactor
            ///
            /// Applies ANSI X9.63 KDF with SHA256 as hashing function.
            /// Requires `kSecKeyKeyExchangeParameterRequestedSize` and allows `kSecKeyKeyExchangeParameterSharedInfo` parameters to be used.
            case ECDHStandardX963SHA256
            /// Compute shared secret using ECDH algorithm without cofactor
            ///
            /// Applies ANSI X9.63 KDF with SHA384 as hashing function.
            /// Requires `kSecKeyKeyExchangeParameterRequestedSize` and allows `kSecKeyKeyExchangeParameterSharedInfo` parameters to be used.
            case ECDHStandardX963SHA384
            /// Compute shared secret using ECDH algorithm without cofactor
            ///
            /// Applies ANSI X9.63 KDF with SHA512 as hashing function.
            /// Requires `kSecKeyKeyExchangeParameterRequestedSize` and allows `kSecKeyKeyExchangeParameterSharedInfo` parameters to be used.
            case ECDHStandardX963SHA512
        }
    }
}

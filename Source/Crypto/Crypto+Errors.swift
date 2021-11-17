// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

/// Errors that can occur during cryptographic operations.
public struct CryptoError: Error {
    let status: OSStatus
}

public extension Crypto {
    /// Errors for asymmetric crypto operations.
    enum AsymmetricCryptoError: Error {
        /// The public key for a private key could not be generated.
        case failedToGetPublicKey
        /// An unsupported crypto operation was attempted.
        case unsupportedOperation(SecKeyOperationType)
    }
}

public extension Crypto {
    /// An error that occurs during AES crypto operations.
    enum AESError: Error, Equatable {
        /// An error that occurs when trying to derive a symmetric encryption key from an invalid password or passphrase.
        case invalidPassword
        /// An error that occurs when trying to derive a symmetric encryption key with an invalid salt.
        case invalidSalt
        /// An error that occurs when an invalid IV size is specified for an AES operation.
        case invalidIVSize(Int)
    }
}

public extension Crypto {
    /// Errors for RSA encrypt and decrypt operations.
    enum RSAError: Error {
        /// The data length for the RSA operation is invalid.
        case invalidDataLength
    }
}

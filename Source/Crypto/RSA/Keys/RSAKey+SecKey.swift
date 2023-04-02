// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

public extension RSAKey where Self: ConvertibleToSecKey & CustomDebugStringConvertible {
    var debugDescription: String { "\(secKey)" }
}

public extension RSAKey where Self: ConvertibleToSecKey {
    var blockSize: Int {
        SecKeyGetBlockSize(secKey)
    }

    /// PKCS#1 data representation of the RSA key.
    ///
    /// Returns the ASN.1 DER encoded format of the key as defined in [PKCS #1 (rfc8017)](https://tools.ietf.org/html/rfc8017).
    /// Also see [On Cryptographic Key Formats](https://developer.apple.com/forums/thread/680554).
    var pkcs1Representation: Data {
        expectNoError {
            try secKey.externalRepresentation()
        }
    }

    func maxPlainTextLength(for algorithm: Crypto.RSA.EncryptionAlgorithm) -> Int? {
        switch algorithm {
        case .raw:
            return blockSize
        case .pkcs1:
            return blockSize - 11
        case .oaepSHA1:
            return blockSize - 2 - (2 * 20)
        case .oaepSHA224:
            return blockSize - 2 - (2 * 28)
        case .oaepSHA256:
            return blockSize - 2 - (2 * 32)
        case .oaepSHA384:
            return blockSize - 2 - (2 * 48)
        case .oaepSHA512:
            return blockSize - 2 - (2 * 64)
        default:
            return nil
        }
    }
}

public extension RSAKey where Self: CreateableFromSecKey & DefinesSecKeyClass {
    /// Creates an RSA key from its PKCS#1 representation.
    ///
    /// The key has to be in ASN.1 DER encoded format as defined in [RFC 8017 - PKCS #1](https://tools.ietf.org/html/rfc8017).
    ///
    /// - Parameter pkcs1Representation: PKCS#1 data of the key.
    init(pkcs1Representation: some ContiguousBytes) throws {
        let secKey: SecKey = try pkcs1Representation.withUnsafeBytes {
            try SecKey.create(keyClass: Self.secKeyClass, keyData: Data($0))
        }

        try self.init(secKey: secKey)
    }
}

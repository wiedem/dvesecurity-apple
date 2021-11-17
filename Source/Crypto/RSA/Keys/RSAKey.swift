// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

/// A type for a asymmetic RSA key.
public protocol RSAKey {
    /// The block length associated with the RSA key.
    var blockSize: Int { get }

    /// Returns the max plaintext length for the given algorithm.
    ///
    /// - Parameter algorithm: The RSA algorithm for which the max length should be returned.
    ///
    /// - Returns: `nil` if the algorithm doesn't have a limit, the maximum size in bytes otherwise.
    func maxPlainTextLength(for algorithm: Crypto.RSA.EncryptionAlgorithm) -> Int?
}

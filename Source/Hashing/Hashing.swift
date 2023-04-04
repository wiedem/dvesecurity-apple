// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import CommonCrypto
import Foundation

/// A type which is able to creat digest codes from arbitrary data.
public protocol HashFunction {
    /// The digest length in bytes.
    static var byteCount: Int { get }

    /// The number of bytes that represents the hash function’s internal state.
    static var blockByteCount: Int { get }

    /// Computes the digest of the bytes in the given data instance and returns the computed digest.
    ///
    /// - Parameters:
    ///   - source: The data whose digest the hash function should compute.
    ///
    /// - Returns: The computed digest of the data.
    static func hash<D>(_ data: D) -> Data where D: DataProtocol

    /// Creates a hash function.
    init()

    /// Incrementally updates the hash function with the given data.
    ///
    ///  Call this method one or more times to provide data to the hash function in blocks. After providing the last block of data, call the ``finalize()`` method to get the computed digest. Don’t call the update method again after finalizing the hash function.
    ///
    /// - Parameters:
    ///   - data: The next block of data for the ongoing digest calculation.
    mutating func update<D>(data: D) where D: DataProtocol

    /// Finalizes the hash function and returns the computed digest.
    ///
    /// Call this method after you provide the hash function with all the data to hash using one or more calls to the ``update(data:)`` method. After finalizing the hash function, discard it. To compute a new digest, create a new hash function with a call to the ``init()`` method.
    ///
    /// - Returns: The computed digest of the data.
    mutating func finalize() -> Data
}

/// A type representing a CommonCrypto HMAC algorithm.
public protocol CCHmacAlgorithmMapping {
    static var ccHmacAlgorithm: CCHmacAlgorithm { get }
}

/// A container for hashing types and methods.
public enum Hashing {
    /// A container for older, cryptographically insecure hashing algorithms.
    public enum Insecure {}
}

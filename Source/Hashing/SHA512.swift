// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import CommonCrypto
import Foundation

public extension Hashing {
    /// An implementation of Secure Hashing Algorithm 2 (SHA-2) hashing with a 512-bit digest.
    struct SHA512: HashFunction {
        /// The number of bytes in a SHA512 digest.
        public static var byteCount: Int { Int(CC_SHA512_DIGEST_LENGTH) }

        /// The block size in bytes for a SHA512 digest.
        public static var blockByteCount: Int { Int(CC_SHA512_BLOCK_BYTES) }

        /// Computes the SHA512 digest of the bytes in the given data instance and returns the computed digest.
        ///
        /// - Parameter source: The data whose digest the hash function should compute. This can be any type that conforms to `DataProtocol`, like `Data` or an array of `UInt8` instances.
        ///
        /// - Returns: The computed digest of the data.
        public static func hash<D>(_ source: D) -> Data where D: DataProtocol {
            let data = Data(source)
            let dataLength = CC_LONG(data.count)
            var digest = Data(count: byteCount)

            digest.withUnsafeMutableBytes { (digestPointer: UnsafeMutableRawBufferPointer) in
                data.withUnsafeBytes { (dataPointer: UnsafeRawBufferPointer) in
                    _ = CC_SHA512(dataPointer.baseAddress!, dataLength, digestPointer.bindMemory(to: UInt8.self).baseAddress!)
                }
            }
            return digest
        }

        private var hashContext = CC_SHA512_CTX()

        /// Creates a SHA512 hash function.
        public init() {
            withUnsafeMutablePointer(to: &hashContext) { _ = CC_SHA512_Init($0) }
        }

        /// Incrementally updates the hash function with the given data.
        ///
        /// Call this method one or more times to provide data to the hash function in blocks.
        /// After providing the last block of data, call the `finalize()` method to get the computed digest.
        /// Don’t call the `update` method again after finalizing the hash function.
        ///
        /// - Parameter data: The next block of data for the ongoing digest calculation. You can provide this as any type that conforms to `DataProtocol`, like `Data` or an array of `UInt8` instances.
        public mutating func update<D>(data: D) where D: DataProtocol {
            let dataToHash = Data(data)
            let dataLength = CC_LONG(data.count)

            withUnsafeMutablePointer(to: &hashContext) { hashContextPointer in
                dataToHash.withUnsafeBytes { (dataToHashPointer: UnsafeRawBufferPointer) in
                    _ = CC_SHA512_Update(hashContextPointer, dataToHashPointer.baseAddress!, dataLength)
                }
            }
        }

        /// Finalizes the hash function and returns the computed digest.
        ///
        /// Call this method after you provide the hash function with all the data to hash by making one or more calls to the `update(data:)` method.
        /// After finalizing the hash function, discard it.
        /// To compute a new digest, create a new hash function with a call to the `init()` method.
        ///
        /// - Returns: The computed digest of the data.
        public mutating func finalize() -> Data {
            var digest = Data(count: Self.byteCount)

            withUnsafeMutablePointer(to: &hashContext) { hashContextPointer in
                digest.withUnsafeMutableBytes { (digestPointer: UnsafeMutableRawBufferPointer) in
                    _ = CC_SHA512_Final(digestPointer.bindMemory(to: UInt8.self).baseAddress, hashContextPointer)
                }
            }
            return digest
        }
    }
}

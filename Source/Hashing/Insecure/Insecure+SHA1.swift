// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import CommonCrypto
import Foundation

public extension Hashing.Insecure {
    enum SHA1 {
        public static var byteCount: Int { Int(CC_SHA1_DIGEST_LENGTH) }
        public static var blockByteCount: Int { Int(CC_SHA1_BLOCK_BYTES) }

        public static func hash(_ source: some DataProtocol) -> Data {
            let data = Data(source)
            let dataLength = CC_LONG(data.count)
            var digest = Data(count: byteCount)

            digest.withUnsafeMutableBytes { (digestPointer: UnsafeMutableRawBufferPointer) in
                data.withUnsafeBytes { (dataPointer: UnsafeRawBufferPointer) in
                    _ = CC_SHA1(dataPointer.baseAddress!, dataLength, digestPointer.bindMemory(to: UInt8.self).baseAddress!)
                }
            }
            return digest
        }
    }
}

// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

public extension ContiguousBytes {
    /// Creates a Data representation to the raw bytes.
    ///
    /// The returned Data object will point to the same memory as this instance as long as neither the returned Data nor this instance is being mutated.
    ///
    /// See [Data(bytesNoCopy:count:deallocator:)](https://developer.apple.com/documentation/foundation/data/1780455-init)
    var dataNoCopy: Data {
        withUnsafeBytes { buffer in
            guard let baseAddress = buffer.baseAddress else {
                return Data()
            }

            let rawPointer = UnsafeMutableRawPointer(mutating: baseAddress)
            return Data(bytesNoCopy: rawPointer, count: buffer.count, deallocator: .none)
        }
    }
}

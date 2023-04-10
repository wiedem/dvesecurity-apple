// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

/// A type that manages sensitive data such as passwords and cryptographic keys in memory.
///
/// Implementations of this type ensure that the underlying managed data is kept in memory for the minimum amount of time possible and is written over when no longer needed.
///
/// When the data is moved in memory, it is ensured that the data is overwritten at the old memory address and thus cannot be reconstructed or read.
/// Implementations should ensure that data is not transferred unintentionally such as in a swap out process.
public protocol SecureData: ContiguousBytes {
    /// The number of bytes contained by the secure data object.
    var byteCount: Int { get }
}

public extension SecureData {
    /// The number of bits contained by the secure data object.
    var bitCount: Int { byteCount * 8 }
}

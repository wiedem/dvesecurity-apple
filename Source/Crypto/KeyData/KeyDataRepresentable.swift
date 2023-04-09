// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

/// A type that can be converted to and from a ``Crypto/KeyData``.
public protocol KeyDataRepresentable {
    /// The ``Crypto/KeyData`` representation of the type.
    var keyData: Crypto.KeyData { get }

    /// Creates a new instance with the specified ``Crypto/KeyData``.
    ///
    /// Implementations may create a copy of the key or hold a strong reference to it.
    ///
    /// - Parameter keyData: The ``Crypto/KeyData`` to use for the new instance.
    init(keyData: Crypto.KeyData) throws
}

public extension KeyDataRepresentable {
    var byteCount: Int { keyData.byteCount }
}

public extension KeyDataRepresentable where Self: ContiguousBytes {
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try keyData.withUnsafeBytes(body)
    }
}

public extension KeyDataRepresentable where Self: Equatable {
    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.keyData == rhs.keyData
    }
}

public extension KeyDataRepresentable where Self: Hashable {
    func hash(into hasher: inout Hasher) {
        keyData.hash(into: &hasher)
    }
}

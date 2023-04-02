// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

public extension ECCKey where Self: ConvertibleToSecKey & CustomDebugStringConvertible {
    var debugDescription: String { "\(secKey)" }
}

public extension ECCKey where Self: X963Convertible & DefinesSecKeyClass & ConvertibleToSecKey {
    var secKey: SecKey {
        expectNoError {
            try SecKey.create(keyClass: Self.secKeyClass, keyData: x963Representation)
        }
    }
}

public extension ECCKey where Self: ConvertibleToSecKey {
    /// X.963 representation of the key.
    ///
    /// See [On Cryptographic Key Formats](https://developer.apple.com/forums/thread/680554).
    var x963Representation: Data {
        expectNoError {
            try secKey.externalRepresentation()
        }
    }
}

public extension ECCKey where Self: CreateableFromSecKey & DefinesSecKeyClass {
    /// Creates a new ECC key from its X.963 representation.
    init(x963Representation: some ContiguousBytes) throws {
        let secKey: SecKey = try x963Representation.withUnsafeBytes {
            try SecKey.create(keyClass: Self.secKeyClass, keyData: Data($0))
        }

        try self.init(secKey: secKey)
    }
}

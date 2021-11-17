// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

public extension Crypto.ECC {
    /// A Elliptic Curve Cryptography public key.
    struct PublicKey: ECCPublicKey, SecKeyConvertible, CustomDebugStringConvertible {
        public let secKey: SecKey

        public init(secKey: SecKey) throws {
            let (secKeyClass, _) = Self.secKeyAttributes(for: secKey)
            guard let keyClass = secKeyClass, keyClass == Self.secKeyClass else {
                throw Crypto.KeyError.invalidSecKey
            }
            self.secKey = secKey
        }
    }
}

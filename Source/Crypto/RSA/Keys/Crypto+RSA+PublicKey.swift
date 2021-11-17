// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

public extension Crypto.RSA {
    /// A RSA public key.
    struct PublicKey: RSAPublicKey {
        public let secKey: SecKey

        /// Creates a new RSA public key from a given `SecKey`.
        ///
        /// - Parameter secKey: The `SecKey` from which the RSA public key should be created.
        ///
        /// - Throws: ``Crypto/KeyError/invalidSecKey`` if the SecKey is no valid RSA public key.
        public init(secKey: SecKey) throws {
            let (secKeyClass, _) = Self.secKeyAttributes(for: secKey)
            guard let keyClass = secKeyClass, keyClass == Self.secKeyClass else {
                throw Crypto.KeyError.invalidSecKey
            }
            self.secKey = secKey
        }
    }
}

extension Crypto.RSA.PublicKey: PKCS1Convertible, X509Convertible, SecKeyConvertible, CustomDebugStringConvertible {}

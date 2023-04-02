// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import CommonCrypto
import Foundation

public extension Crypto {
    /// A hash-based message authentication algorithm.
    struct HMAC<H> where H: HashFunction & CCHmacAlgorithmMapping {
        /// Computes a message authentication code for the given data.
        ///
        /// - Parameters:
        ///   - data: The data for which to compute the authentication code.
        ///   - key: The symmetric key used to secure the computation.
        ///   - hashFunction: The hash function to use for the computation.
        ///
        /// - Returns: The authentication code.
        public static func authenticationCode(
            for data: some DataProtocol,
            using key: some SymmetricKey & RawKeyConvertible
        ) -> Data {
            let sourceData = Data(data)
            var hmacData = Data(count: H.byteCount)
            let keyData = key.rawKeyRepresentation

            hmacData.withUnsafeMutableBytes { (hmacDataPointer: UnsafeMutableRawBufferPointer) in
                keyData.withUnsafeBytes { keyPointer in
                    sourceData.withUnsafeBytes { sourceDataPointer in
                        CCHmac(
                            H.ccHmacAlgorithm,
                            keyPointer.baseAddress!,
                            keyData.count,
                            sourceDataPointer.baseAddress!,
                            sourceData.count,
                            hmacDataPointer.baseAddress
                        )
                    }
                }
            }
            return hmacData
        }

        /// Returns a Boolean indicating whether the given code is valid for a block of data.
        ///
        /// - Parameters:
        ///   - authenticationCode: The authentication code.
        ///   - authenticatedData: The authenticated data.
        ///   - key: The symmetric key used to secure the computation.
        ///
        /// - Returns: Returns `true` iif the authentication code is valid for the given authenticated data, `false` otherwise.
        public static func isValidAuthenticationCode(
            _ authenticationCode: Data,
            authenticating authenticatedData: some DataProtocol,
            using key: some SymmetricKey & RawKeyConvertible
        ) -> Bool {
            return authenticationCode == self.authenticationCode(for: authenticatedData, using: key)
        }

        private var hmacContext = CCHmacContext()

        /// Creates a message authentication code generator.
        ///
        /// - Parameter key: The symmetric key used to secure the computation.
        public init(key: some SymmetricKey & RawKeyConvertible) {
            let keyData = key.rawKeyRepresentation

            withUnsafeMutablePointer(to: &hmacContext) { hmacContextPointer in
                keyData.withUnsafeBytes { keyPointer in
                    CCHmacInit(hmacContextPointer, H.ccHmacAlgorithm, keyPointer.baseAddress!, keyData.count)
                }
            }
        }

        /// Updates the message authentication code computation with a block of data.
        ///
        /// - Parameter data: The data for which to compute the authentication code.
        public mutating func update(data: some DataProtocol) {
            let sourceData = Data(data)

            withUnsafeMutablePointer(to: &hmacContext) { hmacContextPointer in
                sourceData.withUnsafeBytes { (sourceDataPointer: UnsafeRawBufferPointer) in
                    CCHmacUpdate(hmacContextPointer, sourceDataPointer.baseAddress!, sourceData.count)
                }
            }
        }

        /// Finalizes the message authentication computation and returns the computed code.
        ///
        /// - Returns: The authentication code.
        public mutating func finalize() -> Data {
            var hmac = Data(count: H.byteCount)

            withUnsafeMutablePointer(to: &hmacContext) { hmacContextPointer in
                hmac.withUnsafeMutableBytes { (hmacPointer: UnsafeMutableRawBufferPointer) in
                    CCHmacFinal(hmacContextPointer, hmacPointer.baseAddress)
                }
            }
            return hmac
        }
    }
}

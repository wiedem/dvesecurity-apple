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
        ///   - keyData: The symmetric key data used to secure the computation.
        ///   - hashFunction: The hash function to use for the computation.
        ///
        /// - Returns: The authentication code.
        public static func authenticationCode(
            for data: some DataProtocol,
            keyData: some SecureData
        ) -> Data {
            let sourceData = Data(data)
            var hmacData = Data(count: H.byteCount)

            hmacData.withUnsafeMutableBytes { (hmacDataPointer: UnsafeMutableRawBufferPointer) in
                keyData.withUnsafeBytes { keyPointer in
                    sourceData.withUnsafeBytes { sourceDataPointer in
                        CCHmac(
                            H.ccHmacAlgorithm,
                            keyPointer.baseAddress!,
                            keyData.byteCount,
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
        ///   - keyData: The symmetric key data used to secure the computation.
        ///
        /// - Returns: Returns `true` iif the authentication code is valid for the given authenticated data, `false` otherwise.
        public static func isValidAuthenticationCode(
            _ authenticationCode: Data,
            authenticating authenticatedData: some DataProtocol,
            keyData: some SecureData
        ) -> Bool {
            let expectedCode = self.authenticationCode(for: authenticatedData, keyData: keyData)
            guard expectedCode.count == authenticationCode.count else {
                return false
            }

            return authenticationCode.withUnsafeBytes { codeBuffer in
                expectedCode.withUnsafeBytes { expectedCodeBuffer in
                    timingsafe_bcmp(codeBuffer.baseAddress!, expectedCodeBuffer.baseAddress!, expectedCode.count) == 0
                }
            }
        }

        private var hmacContext = CCHmacContext()

        /// Creates a message authentication code generator.
        ///
        /// - Parameter keyData: The symmetric key data used to secure the computation.
        public init(keyData: some SecureData) {
            withUnsafeMutablePointer(to: &hmacContext) { hmacContextPointer in
                keyData.withUnsafeBytes { keyPointer in
                    CCHmacInit(hmacContextPointer, H.ccHmacAlgorithm, keyPointer.baseAddress!, keyData.byteCount)
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

public extension Crypto.HMAC {
    init(key: some KeyDataRepresentable) {
        self.init(keyData: key.keyData)
    }

    static func authenticationCode(
        for data: some DataProtocol,
        key: some KeyDataRepresentable
    ) -> Data {
        authenticationCode(for: data, keyData: key.keyData)
    }

    static func isValidAuthenticationCode(
        _ authenticationCode: Data,
        authenticating authenticatedData: some DataProtocol,
        key: some KeyDataRepresentable
    ) -> Bool {
        isValidAuthenticationCode(authenticationCode, authenticating: authenticatedData, keyData: key.keyData)
    }
}

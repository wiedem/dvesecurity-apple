// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import CommonCrypto
import Foundation

extension Crypto.AES {
    // swiftlint:disable:next function_parameter_count
    static func cryptOperation(
        _ operation: CCOperation,
        algorithm: CCAlgorithm,
        options: CCOptions,
        for data: some ContiguousBytes,
        withKey key: some ContiguousBytes,
        iv: Data // swiftlint:disable:this identifier_name
    ) throws -> Data {
        guard iv.count == blockSize else {
            throw Crypto.AESError.invalidIVSize(blockSize)
        }

        var cryptData = Data()
        var cryptDataLength = 0
        var outputLength = 0

        let result: CCCryptorStatus = withUnsafeMutablePointer(to: &outputLength) { outputLengthPointer in
            data.withUnsafeBytes { dataBuffer in
                cryptDataLength = dataBuffer.count
                if operation == kCCEncrypt {
                    // Add data length needed for the padding.
                    cryptDataLength += blockSize - (dataBuffer.count % blockSize)
                }
                cryptData.count = cryptDataLength

                return cryptData.withUnsafeMutableBytes { cryptDataBuffer in
                    key.withUnsafeBytes { keyBuffer in
                        iv.withUnsafeBytes { ivBuffer in
                            return CCCrypt(
                                operation,
                                algorithm,
                                options,
                                keyBuffer.baseAddress,
                                keyBuffer.count,
                                ivBuffer.baseAddress,
                                dataBuffer.baseAddress,
                                dataBuffer.count,
                                cryptDataBuffer.baseAddress,
                                cryptDataLength,
                                outputLengthPointer
                            )
                        }
                    }
                }
            }
        }

        guard result == kCCSuccess else {
            throw CommonCryptoError(status: result)
        }

        // Make sure the size of the data has the actual output size.
        // We're workign 'in-place' here so we don't need to copy data.
        let bytesToRemove = cryptDataLength - outputLength
        if bytesToRemove > 0 {
            cryptData.removeLast(bytesToRemove)
        }

        return cryptData
    }
}

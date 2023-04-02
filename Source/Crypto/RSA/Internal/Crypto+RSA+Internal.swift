// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

extension Crypto.RSA.EncryptionAlgorithm {
    var secKeyAlgorithm: SecKeyAlgorithm {
        switch self {
        case .raw:
            return .rsaEncryptionRaw
        case .pkcs1:
            return .rsaEncryptionPKCS1
        case .oaepSHA1:
            return .rsaEncryptionOAEPSHA1
        case .oaepSHA224:
            return .rsaEncryptionOAEPSHA224
        case .oaepSHA256:
            return .rsaEncryptionOAEPSHA256
        case .oaepSHA384:
            return .rsaEncryptionOAEPSHA384
        case .oaepSHA512:
            return .rsaEncryptionOAEPSHA512
        case .oaepSHA1AESGCM:
            return .rsaEncryptionOAEPSHA1AESGCM
        case .oaepSHA224AESGCM:
            return .rsaEncryptionOAEPSHA224AESGCM
        case .oaepSHA256AESGCM:
            return .rsaEncryptionOAEPSHA256AESGCM
        case .oaepSHA384AESGCM:
            return .rsaEncryptionOAEPSHA384AESGCM
        case .oaepSHA512AESGCM:
            return .rsaEncryptionOAEPSHA512AESGCM
        }
    }
}

extension Crypto.RSA.MessageSignatureAlgorithm {
    var secKeyAlgorithm: SecKeyAlgorithm {
        switch self {
        case .pkcs1v15SHA1:
            return .rsaSignatureMessagePKCS1v15SHA1
        case .pkcs1v15SHA224:
            return .rsaSignatureMessagePKCS1v15SHA224
        case .pkcs1v15SHA256:
            return .rsaSignatureMessagePKCS1v15SHA256
        case .pkcs1v15SHA384:
            return .rsaSignatureMessagePKCS1v15SHA384
        case .pkcs1v15SHA512:
            return .rsaSignatureMessagePKCS1v15SHA512
        case .pssSHA1:
            return .rsaSignatureMessagePSSSHA1
        case .pssSHA224:
            return .rsaSignatureMessagePSSSHA224
        case .pssSHA256:
            return .rsaSignatureMessagePSSSHA256
        case .pssSHA384:
            return .rsaSignatureMessagePSSSHA384
        case .pssSHA512:
            return .rsaSignatureMessagePSSSHA512
        }
    }
}

extension Crypto.RSA.DigestSignatureAlgorithm {
    var secKeyAlgorithm: SecKeyAlgorithm {
        switch self {
        case .pkcs1v15Raw:
            return .rsaSignatureDigestPKCS1v15Raw
        case .pkcs1v15SHA1:
            return .rsaSignatureDigestPKCS1v15SHA1
        case .pkcs1v15SHA224:
            return .rsaSignatureDigestPKCS1v15SHA224
        case .pkcs1v15SHA256:
            return .rsaSignatureDigestPKCS1v15SHA256
        case .pkcs1v15SHA384:
            return .rsaSignatureDigestPKCS1v15SHA384
        case .pkcs1v15SHA512:
            return .rsaSignatureDigestPKCS1v15SHA512
        case .pssSHA1:
            return .rsaSignatureDigestPSSSHA1
        case .pssSHA224:
            return .rsaSignatureDigestPSSSHA224
        case .pssSHA256:
            return .rsaSignatureDigestPSSSHA256
        case .pssSHA384:
            return .rsaSignatureDigestPSSSHA384
        case .pssSHA512:
            return .rsaSignatureDigestPSSSHA512
        }
    }
}

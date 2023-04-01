// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

extension Crypto.RSA.EncryptionAlgorithm {
    var secKeyAlgorithm: SecKeyAlgorithm {
        switch self {
        case .raw:
            return .rsaEncryptionRaw
        case .PKCS1:
            return .rsaEncryptionPKCS1
        case .OAEPSHA1:
            return .rsaEncryptionOAEPSHA1
        case .OAEPSHA224:
            return .rsaEncryptionOAEPSHA224
        case .OAEPSHA256:
            return .rsaEncryptionOAEPSHA256
        case .OAEPSHA384:
            return .rsaEncryptionOAEPSHA384
        case .OAEPSHA512:
            return .rsaEncryptionOAEPSHA512
        case .OAEPSHA1AESGCM:
            return .rsaEncryptionOAEPSHA1AESGCM
        case .OAEPSHA224AESGCM:
            return .rsaEncryptionOAEPSHA224AESGCM
        case .OAEPSHA256AESGCM:
            return .rsaEncryptionOAEPSHA256AESGCM
        case .OAEPSHA384AESGCM:
            return .rsaEncryptionOAEPSHA384AESGCM
        case .OAEPSHA512AESGCM:
            return .rsaEncryptionOAEPSHA512AESGCM
        }
    }
}

extension Crypto.RSA.MessageSignatureAlgorithm {
    var secKeyAlgorithm: SecKeyAlgorithm {
        switch self {
        case .PKCS1v15SHA1:
            return .rsaSignatureMessagePKCS1v15SHA1
        case .PKCS1v15SHA224:
            return .rsaSignatureMessagePKCS1v15SHA224
        case .PKCS1v15SHA256:
            return .rsaSignatureMessagePKCS1v15SHA256
        case .PKCS1v15SHA384:
            return .rsaSignatureMessagePKCS1v15SHA384
        case .PKCS1v15SHA512:
            return .rsaSignatureMessagePKCS1v15SHA512
        case .PSSSHA1:
            return .rsaSignatureMessagePSSSHA1
        case .PSSSHA224:
            return .rsaSignatureMessagePSSSHA224
        case .PSSSHA256:
            return .rsaSignatureMessagePSSSHA256
        case .PSSSHA384:
            return .rsaSignatureMessagePSSSHA384
        case .PSSSHA512:
            return .rsaSignatureMessagePSSSHA512
        }
    }
}

extension Crypto.RSA.DigestSignatureAlgorithm {
    var secKeyAlgorithm: SecKeyAlgorithm {
        switch self {
        case .PKCS1v15Raw:
            return .rsaSignatureDigestPKCS1v15Raw
        case .PKCS1v15SHA1:
            return .rsaSignatureDigestPKCS1v15SHA1
        case .PKCS1v15SHA224:
            return .rsaSignatureDigestPKCS1v15SHA224
        case .PKCS1v15SHA256:
            return .rsaSignatureDigestPKCS1v15SHA256
        case .PKCS1v15SHA384:
            return .rsaSignatureDigestPKCS1v15SHA384
        case .PKCS1v15SHA512:
            return .rsaSignatureDigestPKCS1v15SHA512
        case .PSSSHA1:
            return .rsaSignatureDigestPSSSHA1
        case .PSSSHA224:
            return .rsaSignatureDigestPSSSHA224
        case .PSSSHA256:
            return .rsaSignatureDigestPSSSHA256
        case .PSSSHA384:
            return .rsaSignatureDigestPSSSHA384
        case .PSSSHA512:
            return .rsaSignatureDigestPSSSHA512
        }
    }
}

// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

extension Crypto.RSA.EncryptionAlgorithm {
    var secKeyAlgorithm: SecKeyAlgorithm {
        switch self {
        case .raw: return SecKeyAlgorithm.rsaEncryptionRaw
        case .PKCS1: return SecKeyAlgorithm.rsaEncryptionPKCS1
        case .OAEPSHA1: return SecKeyAlgorithm.rsaEncryptionOAEPSHA1
        case .OAEPSHA224: return SecKeyAlgorithm.rsaEncryptionOAEPSHA224
        case .OAEPSHA256: return SecKeyAlgorithm.rsaEncryptionOAEPSHA256
        case .OAEPSHA384: return SecKeyAlgorithm.rsaEncryptionOAEPSHA384
        case .OAEPSHA512: return SecKeyAlgorithm.rsaEncryptionOAEPSHA512
        case .OAEPSHA1AESGCM: return SecKeyAlgorithm.rsaEncryptionOAEPSHA1AESGCM
        case .OAEPSHA224AESGCM: return SecKeyAlgorithm.rsaEncryptionOAEPSHA224AESGCM
        case .OAEPSHA256AESGCM: return SecKeyAlgorithm.rsaEncryptionOAEPSHA256AESGCM
        case .OAEPSHA384AESGCM: return SecKeyAlgorithm.rsaEncryptionOAEPSHA384AESGCM
        case .OAEPSHA512AESGCM: return SecKeyAlgorithm.rsaEncryptionOAEPSHA512AESGCM
        }
    }
}

extension Crypto.RSA.SignatureAlgorithm {
    var secKeyMessageAlgorithm: SecKeyAlgorithm {
        switch self {
        case .PKCS1v15SHA1: return SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA1
        case .PKCS1v15SHA224: return SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA224
        case .PKCS1v15SHA256: return SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256
        case .PKCS1v15SHA384: return SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA384
        case .PKCS1v15SHA512: return SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA512
        case .PSSSHA1: return SecKeyAlgorithm.rsaSignatureMessagePSSSHA1
        case .PSSSHA224: return SecKeyAlgorithm.rsaSignatureMessagePSSSHA224
        case .PSSSHA256: return SecKeyAlgorithm.rsaSignatureMessagePSSSHA256
        case .PSSSHA384: return SecKeyAlgorithm.rsaSignatureMessagePSSSHA384
        case .PSSSHA512: return SecKeyAlgorithm.rsaSignatureMessagePSSSHA512
        }
    }

    var secKeyDigestAlgorithm: SecKeyAlgorithm {
        switch self {
        case .PKCS1v15SHA1: return SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA1
        case .PKCS1v15SHA224: return SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA224
        case .PKCS1v15SHA256: return SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA256
        case .PKCS1v15SHA384: return SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA384
        case .PKCS1v15SHA512: return SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA512
        case .PSSSHA1: return SecKeyAlgorithm.rsaSignatureDigestPSSSHA1
        case .PSSSHA224: return SecKeyAlgorithm.rsaSignatureDigestPSSSHA224
        case .PSSSHA256: return SecKeyAlgorithm.rsaSignatureDigestPSSSHA256
        case .PSSSHA384: return SecKeyAlgorithm.rsaSignatureDigestPSSSHA384
        case .PSSSHA512: return SecKeyAlgorithm.rsaSignatureDigestPSSSHA512
        }
    }
}

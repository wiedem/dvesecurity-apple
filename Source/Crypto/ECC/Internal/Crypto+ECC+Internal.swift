// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

extension Crypto.ECC.EncryptionAlgorithm {
    var secKeyAlgorithm: SecKeyAlgorithm {
        switch self {
        case .eciesStandardVariableIVX963SHA224AESGCM:
            return SecKeyAlgorithm.eciesEncryptionStandardVariableIVX963SHA224AESGCM
        case .eciesStandardVariableIVX963SHA256AESGCM:
            return SecKeyAlgorithm.eciesEncryptionStandardVariableIVX963SHA256AESGCM
        case .eciesStandardVariableIVX963SHA384AESGCM:
            return SecKeyAlgorithm.eciesEncryptionStandardVariableIVX963SHA384AESGCM
        case .eciesStandardVariableIVX963SHA512AESGCM:
            return SecKeyAlgorithm.eciesEncryptionStandardVariableIVX963SHA512AESGCM
        case .eciesCofactorVariableIVX963SHA224AESGCM:
            return SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA224AESGCM
        case .eciesCofactorVariableIVX963SHA256AESGCM:
            return SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM
        case .eciesCofactorVariableIVX963SHA384AESGCM:
            return SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA384AESGCM
        case .eciesCofactorVariableIVX963SHA512AESGCM:
            return SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA512AESGCM
        }
    }
}

extension Crypto.ECC.SignatureAlgorithm {
    var secKeyMessageAlgorithm: SecKeyAlgorithm {
        switch self {
        case .ecdsaX962SHA1:
            return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA1
        case .ecdsaX962SHA224:
            return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA224
        case .ecdsaX962SHA256:
            return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
        case .ecdsaX962SHA384:
            return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA384
        case .ecdsaX962SHA512:
            return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA512
        }
    }

    var secKeyDigestAlgorithm: SecKeyAlgorithm {
        switch self {
        case .ecdsaX962SHA1:
            return SecKeyAlgorithm.ecdsaSignatureDigestX962SHA1
        case .ecdsaX962SHA224:
            return SecKeyAlgorithm.ecdsaSignatureDigestX962SHA224
        case .ecdsaX962SHA256:
            return SecKeyAlgorithm.ecdsaSignatureDigestX962SHA256
        case .ecdsaX962SHA384:
            return SecKeyAlgorithm.ecdsaSignatureDigestX962SHA384
        case .ecdsaX962SHA512:
            return SecKeyAlgorithm.ecdsaSignatureDigestX962SHA512
        }
    }
}

extension Crypto.ECC.EllipticCurve {
    var secKeySizeInBits: Int {
        switch self {
        case .p192:
            return 192
        case .p256:
            return 256
        case .p384:
            return 384
        case .p521:
            return 521
        }
    }
}

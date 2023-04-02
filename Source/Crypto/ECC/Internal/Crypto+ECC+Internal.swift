// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

extension Crypto.ECC.EncryptionAlgorithm {
    var secKeyAlgorithm: SecKeyAlgorithm {
        switch self {
        case .ECIESStandardVariableIVX963SHA224AESGCM:
            return SecKeyAlgorithm.eciesEncryptionStandardVariableIVX963SHA224AESGCM
        case .ECIESStandardVariableIVX963SHA256AESGCM:
            return SecKeyAlgorithm.eciesEncryptionStandardVariableIVX963SHA256AESGCM
        case .ECIESStandardVariableIVX963SHA384AESGCM:
            return SecKeyAlgorithm.eciesEncryptionStandardVariableIVX963SHA384AESGCM
        case .ECIESStandardVariableIVX963SHA512AESGCM:
            return SecKeyAlgorithm.eciesEncryptionStandardVariableIVX963SHA512AESGCM
        case .ECIESCofactorVariableIVX963SHA224AESGCM:
            return SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA224AESGCM
        case .ECIESCofactorVariableIVX963SHA256AESGCM:
            return SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM
        case .ECIESCofactorVariableIVX963SHA384AESGCM:
            return SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA384AESGCM
        case .ECIESCofactorVariableIVX963SHA512AESGCM:
            return SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA512AESGCM
        }
    }
}

extension Crypto.ECC.SignatureAlgorithm {
    var secKeyMessageAlgorithm: SecKeyAlgorithm {
        switch self {
        case .ECDSAX962SHA1:
            return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA1
        case .ECDSAX962SHA224:
            return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA224
        case .ECDSAX962SHA256:
            return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
        case .ECDSAX962SHA384:
            return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA384
        case .ECDSAX962SHA512:
            return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA512
        }
    }

    var secKeyDigestAlgorithm: SecKeyAlgorithm {
        switch self {
        case .ECDSAX962SHA1:
            return SecKeyAlgorithm.ecdsaSignatureDigestX962SHA1
        case .ECDSAX962SHA224:
            return SecKeyAlgorithm.ecdsaSignatureDigestX962SHA224
        case .ECDSAX962SHA256:
            return SecKeyAlgorithm.ecdsaSignatureDigestX962SHA256
        case .ECDSAX962SHA384:
            return SecKeyAlgorithm.ecdsaSignatureDigestX962SHA384
        case .ECDSAX962SHA512:
            return SecKeyAlgorithm.ecdsaSignatureDigestX962SHA512
        }
    }
}

extension Crypto.ECC.EllipticCurve {
    var secKeySizeInBits: Int {
        switch self {
        case .P192:
            return 192
        case .P256:
            return 256
        case .P384:
            return 384
        case .P521:
            return 521
        }
    }
}

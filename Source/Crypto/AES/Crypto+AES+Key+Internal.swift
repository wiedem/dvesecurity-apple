// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import CommonCrypto
import Foundation

extension Crypto.AES.Key.PseudoRandomAlgorithm {
    var ccryptoValue: CCPseudoRandomAlgorithm {
        switch self {
        case .hmacAlgSHA1:
            return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1)
        case .hmacAlgSHA224:
            return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA224)
        case .hmacAlgSHA256:
            return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256)
        case .hmacAlgSHA384:
            return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA384)
        case .hmacAlgSHA512:
            return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512)
        }
    }
}

// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

/// Key type of a `SecKey`
public enum SecKeyType: Equatable, Hashable, CaseIterable {
    /// RSA key type.
    case RSA
    /// ECC key type.
    case ECSECPrimeRandom
}

extension SecKeyType {
    var secAttrString: String {
        switch self {
        case .RSA:
            return kSecAttrKeyTypeRSA as String
        case .ECSECPrimeRandom:
            return kSecAttrKeyTypeECSECPrimeRandom as String
        }
    }

    init?(from secAttributes: [String: Any]) {
        guard let keyType = secAttributes[kSecAttrKeyType as String] as? String else {
            return nil
        }

        switch keyType as CFString {
        case kSecAttrKeyTypeRSA:
            self = .RSA
        case kSecAttrKeyTypeEC, kSecAttrKeyTypeECSECPrimeRandom:
            self = .ECSECPrimeRandom
        default:
            return nil
        }
    }
}

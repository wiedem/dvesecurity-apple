// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

/// Key type of a `SecKey`
public enum SecKeyType: Equatable, Hashable, CaseIterable {
    /// RSA key type.
    case rsa
    /// ECC key type.
    case ellipticCurve
}

extension SecKeyType {
    var secAttrString: String {
        switch self {
        case .rsa:
            return kSecAttrKeyTypeRSA as String
        case .ellipticCurve:
            return kSecAttrKeyTypeECSECPrimeRandom as String
        }
    }

    init?(from secAttributes: [String: Any]) {
        guard let keyType = secAttributes[kSecAttrKeyType as String] as? String else {
            return nil
        }

        switch keyType as CFString {
        case kSecAttrKeyTypeRSA:
            self = .rsa
        case kSecAttrKeyTypeEC, kSecAttrKeyTypeECSECPrimeRandom:
            self = .ellipticCurve
        default:
            return nil
        }
    }
}

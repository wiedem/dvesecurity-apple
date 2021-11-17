// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

/// Key class of a `SecKey`.
public enum SecKeyClass: Equatable, Hashable {
    /// A key with an undefined class.
    ///
    /// An unknown or undefined key class. The key type may still be known, in which case the associated value is set accordingly.
    case undefined(SecKeyType?)
    /// A public key for asymmetric cryptographic operations.
    ///
    /// The associated value defines the key type of the key class.
    case `public`(SecKeyType)
    /// A private key for asymmetric cryptographic operations.
    ///
    /// The associated value defines the key type of the key class.
    case `private`(SecKeyType)
    /// A key for symmetric cryptographic operations.
    case symmetric
}

extension SecKeyClass {
    func assertAsymmetricKeyClass() {
        precondition({ () -> Bool in
            switch self {
            case .undefined(.RSA), .undefined(.ECSECPrimeRandom), .public, .private:
                return true
            default:
                return false
            }
        }(), "Expected asymmetric key class but got \(self)")
    }
}

extension SecKeyClass: KeychainQueryParamsConvertible {
    var secAttrString: String? {
        switch self {
        case .undefined: return nil
        case .public: return kSecAttrKeyClassPublic as String
        case .private: return kSecAttrKeyClassPrivate as String
        case .symmetric: return kSecAttrKeyClassSymmetric as String
        }
    }

    init?(from secAttributes: [String: Any]) {
        guard let keyClass = secAttributes[kSecAttrKeyClass as String] as? String else {
            return nil
        }

        switch keyClass as CFString {
        case kSecAttrKeyClassPublic:
            guard let keyType = SecKeyType(from: secAttributes) else { return nil }
            self = .public(keyType)
        case kSecAttrKeyClassPrivate:
            guard let keyType = SecKeyType(from: secAttributes) else { return nil }
            self = .private(keyType)
        case kSecAttrKeyClassSymmetric:
            self = .symmetric
        default:
            return nil
        }
    }

    func insertIntoKeychainQuery(_ query: inout [String: Any]) {
        if let secAttrString = secAttrString {
            query[kSecAttrKeyClass as String] = secAttrString
        }

        switch self {
        case let .undefined(keyType):
            if let keyType = keyType {
                query[kSecAttrKeyType as String] = keyType.secAttrString
            }
        case let .public(keyType), let .private(keyType):
            query[kSecAttrKeyType as String] = keyType.secAttrString
        case .symmetric:
            break
        }
    }
}

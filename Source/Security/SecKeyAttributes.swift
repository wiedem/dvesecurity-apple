// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

/// Attributes of a `SecKey`.
public struct SecKeyAttributes {
    /// The application label attribute of a `SecKey`.
    ///
    /// This attribute is used to look up a key programmatically. In particular, for private and public keys, the value of this attribute is the hash of the public key.
    public let applicationLabel: Data?
    /// Private tag data of a `SecKey`.
    public let applicationTag: String?
    /// The number of bits in the `SecKey`.
    public let keySizeInBits: Int?
    /// A value indicating the effective number of bits in the `SecKey`.
    ///
    /// For example, a DES key has a  ``keySizeInBits`` attribute with a value of 64, but a  ``effectiveKeySize`` attribute with a value of 56.
    public let effectiveKeySize: Int?
    /// The presence of this attribute indicates that item is backed by external token.
    ///
    /// The value of this attribute uniquely identifies the containing token. When this attribute is not present, item is stored in internal keychain database.
    ///
    /// - Note: Note that once item is created, this attribute cannot be changed - in other words it is not possible to migrate existing items to, from or between tokens.
    /// Currently the only available value for this attribute is `kSecAttrTokenIDSecureEnclave`, which indicates that item (private key) is backed by device's Secure Enclave.
    public let tokenID: String?

    public init(
        applicationLabel: Data? = nil,
        applicationTag: String? = nil,
        keySizeInBits: Int? = nil,
        effectiveKeySize: Int? = nil,
        tokenID: String? = nil
    ) {
        self.applicationLabel = applicationLabel
        self.applicationTag = applicationTag
        self.keySizeInBits = keySizeInBits
        self.effectiveKeySize = effectiveKeySize
        self.tokenID = tokenID
    }
}

public extension SecKeyAttributes {
    /// Indicates if the item is stored in the device's Secure Enclave.
    var isBackedBySecureEnclave: Bool {
        tokenID == kSecAttrTokenIDSecureEnclave as String
    }

    init(secAttributes: [String: Any]) {
        if let applicationLabelString = secAttributes[kSecAttrApplicationLabel as String] as? String,
           let applicationLabelData = applicationLabelString.data(using: .utf8)
        {
            applicationLabel = applicationLabelData
        } else if let applicationLabelData = secAttributes[kSecAttrApplicationLabel as String] as? Data {
            applicationLabel = applicationLabelData
        } else {
            applicationLabel = nil
        }

        applicationTag = secAttributes[kSecAttrApplicationTag as String] as? String
        keySizeInBits = secAttributes[kSecAttrKeySizeInBits as String] as? Int
        effectiveKeySize = secAttributes[kSecAttrEffectiveKeySize as String] as? Int
        tokenID = secAttributes[kSecAttrTokenID as String] as? String
    }
}

extension SecKeyAttributes {
    func insertIntoSecParameters(_ parameters: inout [String: Any]) {
        parameters[kSecAttrApplicationLabel as String] = applicationLabel
        parameters[kSecAttrApplicationTag as String] = applicationTag
        parameters[kSecAttrKeySizeInBits as String] = keySizeInBits
        parameters[kSecAttrEffectiveKeySize as String] = effectiveKeySize
        parameters[kSecAttrTokenID as String] = tokenID
    }
}

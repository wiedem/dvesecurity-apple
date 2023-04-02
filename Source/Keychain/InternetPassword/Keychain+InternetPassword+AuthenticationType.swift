// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

public extension Keychain.InternetPassword {
    // swiftlint:disable:next identifier_name
    /// Authentication type attribute of an Internet Password keychain entry.
    enum AuthenticationType {
        case NTLM
        case MSN
        case DPA
        case RPA
        case HTTPBasic
        case HTTPDigest
        case HTMLForm
        case Default
    }
}

// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

public extension Keychain.InternetPassword {
    // swiftlint:disable identifier_name
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
    // swiftlint:enable identifier_name
}

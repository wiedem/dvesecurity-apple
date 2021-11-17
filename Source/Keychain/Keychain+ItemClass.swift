// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

public extension Keychain {
    /// A keychain item class type.
    enum ItemClass: CaseIterable {
        /// Internet password item class.
        case internetPassword
        /// Generic password item class.
        case genericPassword
        /// Certificate item class.
        case certificate
        /// Key item class for symmetric and asymmetric keys.
        case key
        /// Identity item class.
        case identity
    }
}

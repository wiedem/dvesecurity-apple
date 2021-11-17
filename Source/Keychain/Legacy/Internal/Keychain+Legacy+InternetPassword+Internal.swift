// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

#if os(macOS)
extension Keychain.Legacy.InternetPassword {
    static let itemClass: Keychain.ItemClass = .internetPassword
}
#endif

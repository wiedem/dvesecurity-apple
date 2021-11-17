// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

#if os(macOS)
public extension Keychain.Legacy.InternetPassword {
    typealias Item = Keychain.InternetPassword.Item
}
#endif

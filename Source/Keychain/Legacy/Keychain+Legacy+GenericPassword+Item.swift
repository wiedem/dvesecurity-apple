// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

#if os(macOS)
public extension Keychain.Legacy.GenericPassword {
    typealias Item = Keychain.GenericPassword.Item
}
#endif

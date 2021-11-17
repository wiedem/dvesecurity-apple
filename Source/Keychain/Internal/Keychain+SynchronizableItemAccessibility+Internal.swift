// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

extension Keychain.SynchronizableItemAccessibility {
    var secAttrString: String {
        switch self {
        case .always: return kSecAttrAccessibleAlways as String
        case .afterFirstUnlock: return kSecAttrAccessibleAfterFirstUnlock as String
        case .whenUnlocked: return kSecAttrAccessibleWhenUnlocked as String
        }
    }

    init?(secAttrString: String) {
        switch secAttrString as CFString {
        case kSecAttrAccessibleAlways:
            self = .always
        case kSecAttrAccessibleAfterFirstUnlock:
            self = .afterFirstUnlock
        case kSecAttrAccessibleWhenUnlocked:
            self = .afterFirstUnlock
        default:
            return nil
        }
    }
}

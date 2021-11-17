// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

extension Keychain.ItemAccessibility {
    var secAttrString: String {
        switch self {
        case .afterFirstUnlock: return kSecAttrAccessibleAfterFirstUnlock as String
        case .afterFirstUnlockThisDeviceOnly: return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String
        case .whenPasscodeSetThisDeviceOnly: return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly as String
        case .whenUnlocked: return kSecAttrAccessibleWhenUnlocked as String
        case .whenUnlockedThisDeviceOnly: return kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String
        case .always: return kSecAttrAccessibleAlways as String
        case .alwaysThisDeviceOnly: return kSecAttrAccessibleAlwaysThisDeviceOnly as String
        }
    }
}

extension Keychain.ItemAccessibility {
    init?(secAttrString: String) {
        switch secAttrString as CFString {
        case kSecAttrAccessibleAfterFirstUnlock:
            self = .afterFirstUnlock
        case kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly:
            self = .afterFirstUnlockThisDeviceOnly
        case kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly:
            self = .whenPasscodeSetThisDeviceOnly
        case kSecAttrAccessibleWhenUnlocked:
            self = .whenUnlocked
        case kSecAttrAccessibleWhenUnlockedThisDeviceOnly:
            self = .whenUnlockedThisDeviceOnly
        case kSecAttrAccessibleAlways:
            self = .always
        case kSecAttrAccessibleAlwaysThisDeviceOnly:
            self = .alwaysThisDeviceOnly
        default:
            return nil
        }
    }
}

// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

extension Keychain.AccessControl {
    func secAccessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let secAccessControl = SecAccessControlCreateWithFlags(nil, itemAccessibility.secAttrString as CFTypeRef, flags.secAccessControlCreateFlags, &error)
        else {
            throw error!.takeRetainedValue() as Error
        }
        return secAccessControl
    }
}

extension Keychain.AccessControl: KeychainQueryParamsConvertible {
    func insertIntoKeychainQuery(_ query: inout [String: Any]) {
        let accessControl = expectNoError { try secAccessControl() }
        query[kSecAttrAccessControl as String] = accessControl

        if let applicationPasswordPrompt = flags.applicationPasswordPrompt {
            query[kSecUseOperationPrompt as String] = applicationPasswordPrompt
        }
    }
}

extension Keychain.AccessControlFlag {
    var secAccessControlCreateFlags: SecAccessControlCreateFlags {
        switch self {
        case .devicePasscode: return SecAccessControlCreateFlags.devicePasscode
        case .biometryAny: return SecAccessControlCreateFlags.biometryAny
        case .biometryCurrentSet: return SecAccessControlCreateFlags.biometryCurrentSet
        case .userPresence: return SecAccessControlCreateFlags.userPresence
        case .applicationPassword: return SecAccessControlCreateFlags.applicationPassword
        case .privateKeyUsage: return SecAccessControlCreateFlags.privateKeyUsage
        case .satisfyAll: return SecAccessControlCreateFlags.and
        case .satisfyOne: return SecAccessControlCreateFlags.or
        }
    }
}

extension Keychain.AccessControlFlags {
    var secAccessControlCreateFlags: SecAccessControlCreateFlags {
        var secFlags = SecAccessControlCreateFlags()
        forEach { secFlags.update(with: $0.secAccessControlCreateFlags) }
        return secFlags
    }
}

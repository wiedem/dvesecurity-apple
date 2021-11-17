// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

extension Keychain.QueryAuthentication: KeychainQueryParamsConvertible {
    func insertIntoKeychainQuery(_ query: inout [String: Any]) {
        if let authenticationContext = authenticationContext {
            query[kSecUseAuthenticationContext as String] = authenticationContext
        }
        userInterface.insertIntoKeychainQuery(&query)
    }
}

extension Keychain.AuthenticationUI: KeychainQueryParamsConvertible {
    func insertIntoKeychainQuery(_ query: inout [String: Any]) {
        let secUseAuthenticationUI: CFString
        switch self {
        case let .allow(prompt):
            secUseAuthenticationUI = kSecUseAuthenticationUIAllow
            if let prompt = prompt() {
                query[kSecUseOperationPrompt as String] = prompt
            }
        case .disallow:
            secUseAuthenticationUI = kSecUseAuthenticationUIFail
        case .skip:
            secUseAuthenticationUI = kSecUseAuthenticationUISkip
        }
        query[kSecUseAuthenticationUI as String] = secUseAuthenticationUI
    }
}

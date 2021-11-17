// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

/// The type for errors thrown by Keychain methods.
///
/// Some keychain errors have an associated status code of type `OSStatus` produced by the [Security Framework](https://developer.apple.com/documentation/security).
/// Use ``securityErrorMessage(for:)`` to obtain a human readable non-localized string corresponding to the status code.
///
/// See [Security Framework Result Codes](https://developer.apple.com/documentation/security/1542001-security_framework_result_codes/#) for a list of codes.
public enum KeychainError: Error, Equatable {
    /// A keychain query returned an unexpected or unknown result.
    case resultError
    /// A keychain query returned several results although only one was expected.
    case ambiguousQueryResult
    /// The query of an entry in the keychain failed.
    case itemQueryFailed(status: OSStatus)
    /// The saving of the entry in the keychain failed.
    case itemSavingFailed(status: OSStatus)
    /// The update of the entry in the keychain failed.
    case itemUpdateFailed(status: OSStatus)
    /// The deletion of the entry in the keychain failed.
    case itemDeletionFailed(status: OSStatus)
    #if os(macOS)
    /// `SecKeychain` operation failed with an error.
    case secError(status: OSStatus)
    #endif
}

public extension KeychainError {
    /// Returns a human readable non-localized security error string corresponding to the status code.
    func securityErrorMessage(for status: OSStatus) -> String? {
        SecCopyErrorMessageString(status, nil) as String?
    }
}

extension KeychainError: CustomDebugStringConvertible {
    public var debugDescription: String {
        let prefix = String(reflecting: Self.self)

        switch self {
        case .resultError:
            return "\(prefix): unexpected or unknown query result"
        case .ambiguousQueryResult:
            return "\(prefix): ambiguous query result"
        case let .itemQueryFailed(status):
            return "\(prefix): item query failed '\(securityErrorMessage(for: status) ?? "unknown error")' (\(status))"
        case let .itemSavingFailed(status):
            return "\(prefix): item saving failed '\(securityErrorMessage(for: status) ?? "unknown error")' (\(status))"
        case let .itemUpdateFailed(status):
            return "\(prefix): item update failed '\(securityErrorMessage(for: status) ?? "unknown error")' (\(status))"
        case let .itemDeletionFailed(status):
            return "\(prefix): item deletion failed '\(securityErrorMessage(for: status) ?? "unknown error")' (\(status))"
        #if os(macOS)
        case let .secError(status):
            return "\(prefix): SecKeychain operation failed '\(securityErrorMessage(for: status) ?? "unknown error")' (\(status))"
        #endif
        }
    }
}

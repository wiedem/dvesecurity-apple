// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

protocol KeychainQueryParamsConvertible {
    func insertIntoKeychainQuery(_ query: inout [String: Any])
}

extension Sequence where Element: KeychainQueryParamsConvertible {
    func insertIntoKeychainQuery(_ query: inout [String: Any]) {
        forEach { $0.insertIntoKeychainQuery(&query) }
    }
}

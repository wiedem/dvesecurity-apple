// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

protocol KeychainQuery: AnyObject {
    var queryDictionary: [String: Any] { get }
}

protocol KeychainFetchItemsQuery: KeychainQuery {}

protocol KeychainAddItemQuery: KeychainQuery {
    func queryAttributes(_ queryHandler: ([String: Any]) throws -> Void) rethrows
}

protocol KeychainUpdateItemQuery: KeychainQuery {
    func updateAttributes(_ queryHandler: ([String: Any]) throws -> Void) rethrows
}

protocol KeychainDeleteItemsQuery: KeychainQuery {}

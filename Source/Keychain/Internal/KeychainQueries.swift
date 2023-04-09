// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

protocol KeychainQuery: AnyObject {
    var queryDictionary: [String: Any] { get }
}

protocol KeychainFetchItemsQuery: KeychainQuery {}

protocol KeychainAddItemQuery: KeychainQuery {
    var requiresExtendedLifetime: Bool { get }
}

protocol KeychainUpdateItemQuery: KeychainQuery {
    var updateDictionary: [String: Any] { get }
}

protocol KeychainDeleteItemsQuery: KeychainQuery {}

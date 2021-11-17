// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

protocol KeychainQuery {
    var queryDictionary: [String: Any] { get }
}

protocol KeychainFetchItemsQuery: KeychainQuery {}

protocol KeychainAddItemQuery: KeychainQuery {}

protocol KeychainUpdateItemQuery: KeychainQuery {
    var updateDictionary: [String: Any] { get }
}

protocol KeychainDeleteItemsQuery: KeychainQuery {}

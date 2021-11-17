// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

extension Optional {
    @discardableResult
    @inlinable func updateMapped<Element>(_ transform: (Wrapped) -> Element, in set: inout Set<Element>) -> Element? {
        guard case let .some(wrapped) = self else { return nil }
        return set.update(with: transform(wrapped))
    }
}

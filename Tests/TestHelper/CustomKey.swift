// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Foundation

struct CustomKey: RawKeyConvertible {
    var rawKeyRepresentation: Data {
        value.data(using: .utf8)!
    }

    private(set) var value: String

    init(value: String) {
        self.value = value
    }

    init(rawKeyRepresentation: some ContiguousBytes) {
        let data = rawKeyRepresentation.withUnsafeBytes { Data($0) }
        value = String(data: data, encoding: .utf8)!
    }
}

extension CustomKey: Equatable {
    static func == (lhs: Self, rhs: Self) -> Bool {
        return lhs.value == rhs.value
    }
}

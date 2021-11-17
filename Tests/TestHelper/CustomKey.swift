// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Foundation

struct CustomKey: RawKeyConvertible, Equatable {
    static func == (lhs: Self, rhs: Self) -> Bool {
        return lhs.value == rhs.value
    }

    var rawKeyRepresentation: Data {
        value.data(using: .utf8)!
    }

    private(set) var value: String

    init(value: String) {
        self.value = value
    }

    init<Bytes>(rawKeyRepresentation: Bytes) where Bytes: ContiguousBytes {
        let data = rawKeyRepresentation.withUnsafeBytes { Data($0) }
        value = String(data: data, encoding: .utf8)!
    }
}

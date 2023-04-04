// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import SwiftASN1

/// A container for ASN.1 related types and operations.
public enum ASN1 {
    /// An error that occurs when a sequence of DER bytes cannot be converted to a valid Integer representation.
    enum IntegerRepresentableError: Error {
        /// The sequence of DER Integer bytes doesn't represent a valid value.
        case invalidValue(derIntegerBytes: ArraySlice<UInt8>)
    }
}

public extension RawRepresentable where Self: ASN1IntegerRepresentable, RawValue: FixedWidthInteger & ASN1IntegerRepresentable {
    static var isSigned: Bool {
        RawValue.isSigned
    }

    init(derIntegerBytes: ArraySlice<UInt8>) throws {
        let rawValue = try RawValue(derIntegerBytes: derIntegerBytes)

        guard let instance = Self(rawValue: rawValue) else {
            throw ASN1.IntegerRepresentableError.invalidValue(derIntegerBytes: derIntegerBytes)
        }
        self = instance
    }

    func withBigEndianIntegerBytes<ReturnType>(_ body: (RawValue.IntegerBytes) throws -> ReturnType) rethrows -> ReturnType {
        try rawValue.withBigEndianIntegerBytes(body)
    }
}

extension Array: DERImplicitlyTaggable where Element: DERImplicitlyTaggable {
    public static var defaultIdentifier: SwiftASN1.ASN1Identifier {
        .sequence
    }

    public init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            var elements = [Element]()
            while let node = nodes.next() {
                try elements.append(Element(derEncoded: node))
            }
            return Self(elements)
        }
    }

    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.serializeSequenceOf(self, identifier: identifier)
    }
}

extension Array: DERSerializable where Element: DERImplicitlyTaggable {}
extension Array: DERParseable where Element: DERImplicitlyTaggable {}

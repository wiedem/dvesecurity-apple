// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

/// A type that can be converted to and from a raw key representation.
public protocol RawKeyConvertible {
    /// The raw key representation of the type.
    var rawKeyRepresentation: Data { get }

    /// Creates a new instance from a raw key representation of the type.
    ///
    /// - Parameter rawKeyRepresentation: Raw representation of the key.
    init<Bytes>(rawKeyRepresentation: Bytes) throws where Bytes: ContiguousBytes
}

/// A type that can be  converted to and from a PKCS#1 representation.
public protocol PKCS1Convertible {
    /// The PKCS#1 representation of the type.
    var pkcs1Representation: Data { get }

    /// Creates a new instance from a PKCS#1 representation of the type.
    ///
    /// - Parameter pkcs1Representation: PKCS#1 representation of the key.
    init<Bytes>(pkcs1Representation: Bytes) throws where Bytes: ContiguousBytes
}

/// A type that can be  converted to and from a X.509 representation.
public protocol X509Convertible {
    /// The X.509 representation of the type.
    var x509Representation: Data { get }

    /// Creates a new instance from a X.509 representation of the type.
    ///
    /// - Parameter x509Representation: X.509 representation of the key.
    init<Bytes>(x509Representation: Bytes) throws where Bytes: ContiguousBytes
}

/// A type that can be  converted to and from a X.963 representation.
public protocol X963Convertible {
    /// The X.963 representation of the type.
    var x963Representation: Data { get }

    /// Creates a new instance from a X.963 representation of the type.
    ///
    /// - Parameter x963Representation: X.963 representation of the key.
    init<Bytes>(x963Representation: Bytes) throws where Bytes: ContiguousBytes
}

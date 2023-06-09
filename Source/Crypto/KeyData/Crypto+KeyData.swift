// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

public extension Crypto {
    /// A key data object that meets the ``SecureData`` protocol.
    ///
    /// The key data is automatically reset as soon as the key is released.
    ///
    /// The implementation also ensures that the memory pages of the key data are not transferred to a swap area by the operating system.
    ///
    /// The underlying bytes of the key can be accessed with the ``withUnsafeBytes(_:)`` method.
    /// This data should only be accessed for reading and not copied.
    ///
    /// - Note: References to the key should be kept only as long as necessary.
    /// - Note: This type conforms to the [Sendable](https://developer.apple.com/documentation/swift/sendable) protocol, since the data
    /// of the key is immutable.
    final class KeyData: SecureData, Sendable {
        public let byteCount: Int

        private let dataPointer: UnsafeMutablePointer<UInt8>
        private var unsafeRawBufferPointer: UnsafeRawBufferPointer {
            .init(start: dataPointer, count: byteCount)
        }

        /// Creates a new key data object and initializes it using a closure.
        ///
        /// - Parameters:
        ///   - byteCount: The number of bytes for the key data.
        ///   - initializingWith: A closure initializing the memory of the key.
        public init(byteCount: Int, initializingWith callback: (UnsafeMutableRawBufferPointer) throws -> Void) rethrows {
            self.byteCount = byteCount
            dataPointer = .allocate(capacity: byteCount)

            // Make sure the memory is not swapped out.
            mlock(dataPointer, byteCount)

            dataPointer.initialize(repeating: 0, count: byteCount)

            try callback(.init(start: dataPointer, count: byteCount))
        }

        /// Creates a new key data object by transferring data from a dynamic byte buffer.
        ///
        /// During initilization the data from the buffer will be copied.
        /// After the data transfer the data from the source will be overwritten if `resetSource` is set to `true`.
        ///
        /// This method can be used to transfer data from an insecure source to a secure source, which guarantees that the data in memory will be overwritten
        /// as soon as it is no longer needed.
        ///
        /// - Note: The caller has to ensure that there are no other copies of `source` in memory.
        ///
        /// - Parameters:
        ///   - source: A dynamic byte buffer from which the data will be copied.
        ///   - resetSource: Indicates if the source buffer should be reset after the transfer.
        public init(transferFrom source: NSMutableData, resetSource: Bool = true) {
            byteCount = source.length
            dataPointer = .allocate(capacity: byteCount)
            dataPointer.initialize(repeating: 0, count: byteCount)

            let mutableRawBufferPointer = UnsafeMutableRawBufferPointer(mutating: unsafeRawBufferPointer)
            source.copyBytes(to: mutableRawBufferPointer)
            if resetSource {
                source.resetBytes(in: NSRange(location: 0, length: source.length))
            }
        }

        deinit {
            // Reset the bytes of the memory before deallocating it.
            dataPointer.update(repeating: 0, count: byteCount)
            // Make sure the page of the memory can be swapped out again.
            munlock(dataPointer, byteCount)

            dataPointer.deallocate()
        }
    }
}

extension Crypto.KeyData: Hashable {
    public static func == (lhs: Crypto.KeyData, rhs: Crypto.KeyData) -> Bool {
        guard lhs.byteCount == rhs.byteCount else {
            return false
        }
        return memcmp(lhs.dataPointer, rhs.dataPointer, lhs.byteCount) == 0
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(bytes: unsafeRawBufferPointer)
    }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try body(unsafeRawBufferPointer)
    }
}

public extension Crypto.KeyData {
    /// Generates cryptographically secure random key data
    ///
    /// - Parameter length: The number of random bytes of the key.
    static func createRandomData(length: Int) throws -> Self {
        try Self(byteCount: length) { rawBufferPointer in
            let result = SecRandomCopyBytes(kSecRandomDefault, length, rawBufferPointer.baseAddress!)

            guard result == errSecSuccess else {
                throw CryptoError(status: result)
            }
        }
    }

    /// Creates secure key data from a unsecure data source.
    ///
    /// The source data from wich the key data is created is not changed and remains in an unsafe state.
    ///
    /// For Swift high-level data types such as `Data` and `String`, there is no guarantee that the underlying bytes in memory will not be copied multiple times
    /// during the lifetime of the value, leaving multiple data traces behind.
    ///
    /// There is no guarantee that the source data in memory cannot be read by an attacker after the value has been released or that the data will not be moved to
    /// an unsafe swap area by the operating system.
    ///
    /// It is recommended wherever possible to generate data for cryptographic purposes that must be held in memory using secure methods.
    /// Use ``createRandomData(length:)`` if you want to create a random bytes for a key or ``init(transferFrom:resetSource:)`` to transfer
    /// the ownership of memory to the newly created key object and resetting the source memory.
    ///
    /// - Parameter data: The bytes from which the secure data should be created.
    static func createFromUnsafeData(_ data: some DataProtocol) -> Self {
        Self(byteCount: data.count) { mutableRawBufferPointer in
            data.copyBytes(to: mutableRawBufferPointer)
        }
    }

    /// Creates secure key data from a unsecure data source.
    ///
    /// The source data from wich the key data is created is not changed and remains in an unsafe state.
    ///
    /// For Swift high-level data types such as `Data` and `String`, there is no guarantee that the underlying bytes in memory will not be copied multiple times
    /// during the lifetime of the value, leaving multiple data traces behind.
    ///
    /// There is no guarantee that the source data in memory cannot be read by an attacker after the value has been released or that the data will not be moved to
    /// an unsafe swap area by the operating system.
    ///
    /// It is recommended wherever possible to generate data for cryptographic purposes that must be held in memory using secure methods.
    /// Use ``createRandomData(length:)`` if you want to create a random bytes for a key or ``init(transferFrom:resetSource:)`` to transfer
    /// the ownership of memory to the newly created key object and resetting the source memory.
    ///
    /// - Parameter data: The bytes from which the secure data should be created.
    static func createFromUnsafeBytes(_ data: some ContiguousBytes) -> Self {
        data.withUnsafeBytes { sourceBufferPointer in
            Self(byteCount: sourceBufferPointer.count) { mutableRawBufferPointer in
                sourceBufferPointer.copyBytes(to: mutableRawBufferPointer)
            }
        }
    }
}

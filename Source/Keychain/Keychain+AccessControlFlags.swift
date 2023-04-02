// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

// MARK: - AccessControlFlag
public extension Keychain {
    /// Access control constants that dictate how a keychain item may be used.
    enum AccessControlFlag {
        /// Constraint to access an item with a passcode.
        ///
        /// The user interface for query operations (see  ``Keychain/QueryAuthentication/userInterface``) has to be allowed in order to show the passcode prompt.
        /// Otherwise the operation will fail with an error code `errSecInteractionNotAllowed` (-25308).
        case devicePasscode
        /// Constraint to access an item with Touch ID for any enrolled fingers, or Face ID.
        ///
        /// Touch ID must be available and enrolled with at least one finger, or Face ID must be available and enrolled.
        /// The item is still accessible by Touch ID if fingers are added or removed, or by Face ID if the user is re-enrolled.
        case biometryAny
        /// Constraint to access an item with Touch ID for currently enrolled fingers, or from Face ID with the currently enrolled user.
        ///
        /// Touch ID must be available and enrolled with at least one finger, or Face ID available and enrolled.
        /// The item is invalidated if fingers are added or removed for Touch ID, or if the user re-enrolls for Face ID.
        case biometryCurrentSet
        /// Constraint to access an item with either biometry or passcode.
        ///
        /// Tells keychain services to request biometric authentication, or to fall back on the device passcode, whenever the item is read from the keychain.
        ///
        /// Biometry doesn’t have to be available or enrolled. The item is still accessible by Touch ID even if fingers are added or removed, or by Face ID if the user is re-enrolled.
        ///
        /// This option is equivalent to specifying ``satisfyOne``,``biometryAny``,  and ``devicePasscode`` for read operations.
        ///
        /// Note that there's no equivalent option for save operations since any biometry option will always try to tag an item accordingly, no matter if the ``satisfyOne`` flag is specified or not. If the tagging fails during the save operatione because no biometry is available, an error with `errSecAuthFailed` (-25293) will be returned.
        case userPresence
        /// Option to use an application-provided password for data encryption key generation.
        ///
        /// When you add this flag, the system prompts the user for a password when creating the item, and then again before retrieving it.
        /// The item can only be retrieved if the user successfully enters the password, independent of satisfying any other conditions.
        ///
        /// You can specify a localized description the system includes in the user prompt.
        ///
        /// - Important: Note that two `applicationPassword` flag values are considered to be equal no matter what their associated `prompt` value is.
        /// It also means the associated `prompt` value does't influence the hash value of this enum value.
        case applicationPassword(prompt: @autoclosure () -> String? = nil)
        /// Enable a private key to be used in signing a block of data or verifying a signed block.
        ///
        /// This flag indicates that the private key should be available for use in signing and verification operations inside the Secure Enclave.
        ///
        /// Without the flag, key generation still succeeds, but signing operations that attempt to use it fail.
        case privateKeyUsage
        /// Indicates that all constraints must be satisfied.
        case satisfyAll
        /// Indicates that at least one constraint must be satisfied.
        case satisfyOne
    }
}

// MARK: - AccessControlFlags
public extension Keychain {
    /// An unordered set of unique AccessControlFlag elements.
    struct AccessControlFlags {
        private var _flags: Set<AccessControlFlag>

        /// Associated `prompt` value of the `.applicationPassword` flag if the value is set, `nil ` otherwise.
        public var applicationPasswordPrompt: String? {
            guard let index = firstIndex(of: .applicationPassword()) else { return nil }
            if case let .applicationPassword(prompt) = self[index] {
                return prompt()
            }
            return nil
        }

        /// Creates an empty set of access control flags.
        ///
        /// This is equivalent to initializing with an empty array literal.
        public init() {
            _flags = Set<AccessControlFlag>()
        }

        /// Creates an empty access control flag set with preallocated space for at least the specified number of elements.
        ///
        /// Use this initializer to avoid intermediate reallocations of a set's storage buffer when you know how many elements you'll insert into the set after creation.
        ///
        /// - Parameter minimumCapacity: The minimum number of elements that the newly created set should be able to store without reallocating its storage buffer.
        public init(minimumCapacity: Int) {
            _flags = Set<AccessControlFlag>(minimumCapacity: minimumCapacity)
        }

        public init(_ sequence: some Sequence<AccessControlFlag>) {
            _flags = Set<AccessControlFlag>(sequence)
        }

        /// Inserts the given access control flag in the set it is not already present.
        ///
        /// If an element equal to `newMember` is already contained in the set, this method has no effect.
        ///
        /// - Note: Since `.applicationPassword` flags are considered to be equal no matter which `prompt` value is associated with them, trying to insert a new `.applicationPassword` with a different `prompt` won't have any effect. Use `update(:)` instead to replace the `prompt` of an existing `.applicationPassword` value.
        ///
        /// - Parameter newMember: An access control flag to insert into the set.
        ///
        /// - Returns: `(true, newMember)` if `newMember` was not contained in the set. If an element equal to `newMember` was already contained in the set, the method
        /// returns `(false, oldMember)`, where `oldMember` is the element that was equal to `newMember`. In some cases, `oldMember` may be distinguishable from
        /// `newMember` by identity comparison or some other means.
        @discardableResult
        public mutating func insert(_ newMember: AccessControlFlag) -> (inserted: Bool, memberAfterInsert: AccessControlFlag) {
            _flags.insert(newMember)
        }

        /// Inserts the given access control flag into the set unconditionally.
        ///
        /// If an element equal to `newMember` is already contained in the set, `newMember` replaces the existing element.
        ///
        /// - Parameter newMember: An access control flag to insert into the set.
        ///
        /// - Returns: An element equal to `newMember` if the set already contained such a member; otherwise, `nil`. In some cases, the returned element may be distinguishable
        /// from `newMember` by identity comparison or some other means.
        @discardableResult
        public mutating func update(with newMember: AccessControlFlag) -> AccessControlFlag? {
            _flags.update(with: newMember)
        }

        /// Removes the specified access control flag from the set.
        ///
        /// - Note: Removing an `.applicationPassword` flag will remove the value from the set no matter which `prompt` value is associated with it.
        ///
        /// - Parameter member: The access control flag to remove from the set.
        ///
        /// - Returns: The value of the `member` parameter if it was a member of the
        ///   set; otherwise, `nil`.
        @discardableResult
        public mutating func remove(_ member: AccessControlFlag) -> AccessControlFlag? {
            _flags.remove(member)
        }

        /// Removes the access control flag at the given index of the set.
        ///
        /// - Parameter position: The index of the member to remove. `position` must be a valid index of the set, and must not be equal to the set's end index.
        ///
        /// - Returns: The access control flag that was removed from the set.
        public mutating func remove(at position: Index) -> Element {
            _flags.remove(at: position)
        }

        /// Removes all access control flags from the set.
        ///
        /// - Parameter keepingCapacity: If `true`, the set's buffer capacity is preserved; if `false`, the underlying buffer is released. The default is `false`.
        public mutating func removeAll(keepingCapacity keepCapacity: Bool = false) {
            _flags.removeAll(keepingCapacity: keepCapacity)
        }

        /// Removes the first access control flag of the set.
        ///
        /// Because a set is not an ordered collection, the "first" element may not be the first element that was added to the set. The set must not be empty.
        ///
        /// - Complexity: Amortized O(1) if the set does not wrap a bridged `NSSet`.
        ///   If the set wraps a bridged `NSSet`, the performance is unspecified.
        ///
        /// - Returns: A member of the set.
        public mutating func removeFirst() -> AccessControlFlag {
            _flags.removeFirst()
        }
    }
}

// MARK: - AccessControlFlag extensions
extension Keychain.AccessControlFlag: Hashable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        let lhsValue = Mirror(reflecting: lhs).children.first?.label ?? "\(lhs)"
        let rhsValue = Mirror(reflecting: rhs).children.first?.label ?? "\(rhs)"
        return lhsValue == rhsValue
    }

    public func hash(into hasher: inout Hasher) {
        let mirror = Mirror(reflecting: self)
        hasher.combine(mirror.children.first?.label ?? "\(self)")
    }
}

extension Keychain.AccessControlFlag: CaseIterable {
    public static var allCases: [Keychain.AccessControlFlag] {
        return [.devicePasscode, .biometryAny, .biometryCurrentSet,
                .userPresence, .applicationPassword(), .privateKeyUsage,
                .satisfyAll, .satisfyOne]
    }
}

// MARK: - AccessControlFlags extensions
extension Keychain.AccessControlFlags: Collection {
    public typealias Index = Set<Keychain.AccessControlFlag>.Index
    public typealias Element = Keychain.AccessControlFlag

    public var startIndex: Index { return _flags.startIndex }
    public var endIndex: Index { return _flags.endIndex }

    public subscript(index: Index) -> Iterator.Element { return _flags[index] }

    // swiftlint:disable:next identifier_name
    public func index(after i: Index) -> Index {
        _flags.index(after: i)
    }
}

// MARK: - ExpressibleByArrayLiteral
extension Keychain.AccessControlFlags: ExpressibleByArrayLiteral {
    public typealias ArrayLiteralElement = Keychain.AccessControlFlag

    public init(arrayLiteral elements: Element...) {
        _flags = Set<ArrayLiteralElement>(elements)
    }
}

// MARK: - Hashable
extension Keychain.AccessControlFlags: Hashable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        return lhs._flags == rhs._flags &&
            lhs.applicationPasswordPrompt == rhs.applicationPasswordPrompt
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(_flags)
        if let applicationPasswordPrompt {
            hasher.combine(applicationPasswordPrompt)
        }
    }
}

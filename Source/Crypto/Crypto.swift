// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

/// A container for cryptographic types and methods.
public enum Crypto {
    /// An error that occurs during crypto operations when there's an issue with the used key.
    public enum KeyError: Error, Equatable {
        /// An error that occurs during the crypto operation when a key is not a valid `SecKey` for the operation.
        case invalidSecKey
    }

    /// A default set of 96 characters which can be used to create random passwords.
    ///
    /// The alphabet contains the following characters:
    /// ```
    /// "#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~
    /// ```
    ///
    /// This set may be used for ``Crypto/createRandomPassword(length:characters:)``.
    public static let defaultRandomPasswordAlphabet: Set<Character> = {
        return "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
            .reduce(into: Set<Character>()) { result, character in
                result.insert(character)
            }
    }()

    /// Creates a random password.
    ///
    /// - Note: Since the password is generated as a `String` type, it is not guaranteed that it will be removed from memory after use or that no copies will
    /// be created in memory. In certain attack situations, this can lead to the generated password data being reconstructed or read by other processes.
    ///
    /// - Parameters:
    ///   - length: The length of the random password to create.
    ///   - characters: The alphabet of the password.
    ///
    /// - Returns: Random password of the specified length and consisting of characters from the specified alphabet.
    public static func createRandomPassword(length: Int, characters: Set<Character> = defaultRandomPasswordAlphabet) -> String {
        var password = ""
        let charactersArray = Array(characters)
        let charactersIndexRange = 0..<characters.count

        for _ in 1...length {
            password.append(charactersArray[charactersIndexRange.randomElement()!])
        }
        return password
    }
}

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

    /// Creates random data for cryptographic operations.
    ///
    /// - Parameter length: The length of the random data to create.
    ///
    /// - Returns: Random data of the specified length.
    public static func createRandomData(length: Int) throws -> Data {
        var data = Data(count: length)

        let result = data.withUnsafeMutableBytes { (dataPointer: UnsafeMutableRawBufferPointer) in
            return SecRandomCopyBytes(kSecRandomDefault, length, dataPointer.baseAddress!)
        }

        guard result == errSecSuccess else {
            throw CryptoError(status: result)
        }
        return data
    }

    /// Creates a random password for cryptographic operations.
    ///
    /// - Parameters:
    ///   - length: The length of the random password to create.
    ///   - characters: The alphabet of the password.
    ///
    /// - Returns: Random password of the specified length and consisting of characters from the specified alphabet.
    public static func createRandomPassword(length: Int, characters: Set<Character> = defaultRandomPasswordAlphabet) -> String {
        var password = ""
        let charactersArray = Array(characters)

        for _ in 1...length {
            password.append(charactersArray[Int(arc4random_uniform(UInt32(characters.count)))])
        }
        return password
    }
}

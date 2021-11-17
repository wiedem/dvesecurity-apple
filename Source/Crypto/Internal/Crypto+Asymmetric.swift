// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import CommonCrypto
import Foundation
import LocalAuthentication
import Security

extension Crypto {
    enum Asymmetric {
        static func publicKey(for privateKey: SecKey) throws -> SecKey {
            guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
                throw AsymmetricCryptoError.failedToGetPublicKey
            }
            return publicKey
        }

        static func createPrivateKey(keyType: SecKeyType, keySizeInBits: Int) throws -> SecKey {
            let keyGenerationAttributes = SecKeyAttributes(keySizeInBits: keySizeInBits)
            return try createSecKey(keyType: keyType,
                                    keyGenerationAttributes: keyGenerationAttributes,
                                    privateKeyAttributes: .init())
        }

        static func createSecureEnclavePrivateKey() throws -> SecKey {
            let keyGenerationAttributes = SecKeyAttributes(keySizeInBits: Crypto.ECC.EllipticCurve.P256.secKeySizeInBits,
                                                           tokenID: kSecAttrTokenIDSecureEnclave as String)
            return try createSecKey(keyType: .ECSECPrimeRandom,
                                    keyGenerationAttributes: keyGenerationAttributes,
                                    privateKeyAttributes: .init())
        }

        static func encryptDataBlock<D>(_ plainText: D, withKey publicKey: SecKey, algorithm: SecKeyAlgorithm) throws -> Data where D: DataProtocol {
            guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) else {
                throw AsymmetricCryptoError.unsupportedOperation(.encrypt)
            }

            let plainTextData = Data(plainText)
            var error: Unmanaged<CFError>?
            guard let cipherTextData = SecKeyCreateEncryptedData(publicKey,
                                                                 algorithm,
                                                                 plainTextData as CFData,
                                                                 &error)
            else {
                throw error!.takeRetainedValue() as Error
            }
            return cipherTextData as Data
        }

        static func decryptDataBlock<D>(_ cipherText: D, withKey privateKey: SecKey, algorithm: SecKeyAlgorithm) throws -> Data where D: DataProtocol {
            guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, algorithm) else {
                throw AsymmetricCryptoError.unsupportedOperation(.decrypt)
            }

            let cipherTextData = Data(cipherText)
            var error: Unmanaged<CFError>?
            guard let plainTextData = SecKeyCreateDecryptedData(privateKey, algorithm, cipherTextData as CFData, &error) else {
                throw error!.takeRetainedValue() as Error
            }
            return plainTextData as Data
        }

        static func sign<D>(_ data: D, withKey privateKey: SecKey, algorithm: SecKeyAlgorithm) throws -> Data where D: DataProtocol {
            guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
                throw AsymmetricCryptoError.unsupportedOperation(.sign)
            }

            let dataToSign = Data(data)
            var error: Unmanaged<CFError>?
            guard let signature = SecKeyCreateSignature(privateKey, algorithm, dataToSign as CFData, &error) else {
                throw error!.takeRetainedValue() as Error
            }
            return signature as Data
        }

        static func verify<D>(signature: Data, of signedData: D, withKey publicKey: SecKey, algorithm: SecKeyAlgorithm) throws -> Bool where D: DataProtocol {
            guard SecKeyIsAlgorithmSupported(publicKey, .verify, algorithm) else {
                throw AsymmetricCryptoError.unsupportedOperation(.verify)
            }

            let dataToVerify = Data(signedData)
            var error: Unmanaged<CFError>?
            let result = SecKeyVerifySignature(publicKey, algorithm, dataToVerify as CFData, signature as CFData, &error)
            guard error == nil else {
                let nsError = error!.takeRetainedValue() as Error as NSError
                switch (nsError.domain, OSStatus(nsError.code)) {
                case (NSOSStatusErrorDomain, errSecVerifyFailed):
                    return false
                default:
                    throw nsError
                }
            }
            return result
        }
    }
}

extension Crypto.Asymmetric {
    static func createPrivateKeyInKeychain(
        keyType: SecKeyType,
        keySizeInBits: Int,
        tag: String,
        accessGroup: String = Keychain.defaultAccessGroup,
        accessControl: Keychain.AccessControl,
        authenticationContext: LAContext? = nil
    ) throws -> SecKey {
        let keyGenerationAttributes = SecKeyAttributes(keySizeInBits: keySizeInBits)
        let privateKeyAttributes = SecKeyAttributes(applicationTag: tag)

        return try createSecKeyInKeychain(
            keyType: keyType,
            keyGenerationAttributes: keyGenerationAttributes,
            privateKeyAttributes: privateKeyAttributes,
            accessGroup: accessGroup,
            accessControl: accessControl,
            authenticationContext: authenticationContext
        )
    }

    static func createSecureEnclavePrivateKeyInKeychain(
        tag: String,
        accessGroup: String = Keychain.defaultAccessGroup,
        accessControl: Keychain.AccessControl
    ) throws -> SecKey {
        let keyGenerationAttributes = SecKeyAttributes(keySizeInBits: Crypto.ECC.EllipticCurve.P256.secKeySizeInBits,
                                                       tokenID: kSecAttrTokenIDSecureEnclave as String)
        let privateKeyAttributes = SecKeyAttributes(applicationTag: tag)

        return try createSecKeyInKeychain(
            keyType: .ECSECPrimeRandom,
            keyGenerationAttributes: keyGenerationAttributes,
            privateKeyAttributes: privateKeyAttributes,
            accessGroup: accessGroup,
            accessControl: accessControl
        )
    }

    static func createSecKeyInKeychain(
        keyType: SecKeyType,
        keyGenerationAttributes: SecKeyAttributes,
        privateKeyAttributes: SecKeyAttributes,
        accessGroup: String = Keychain.defaultAccessGroup,
        accessControl: Keychain.AccessControl = .afterFirstUnlockThisDeviceOnly,
        authenticationContext: LAContext? = nil
    ) throws -> SecKey {
        precondition(keyGenerationAttributes.keySizeInBits != nil, "Required key attribute 'keySizeInBits' for key generation missing.")

        var secPrivateKeyAttributes = [kSecAttrIsPermanent: true,
                                       kSecAttrAccessGroup: accessGroup] as [String: Any]
        accessControl.insertIntoKeychainQuery(&secPrivateKeyAttributes)
        privateKeyAttributes.insertIntoSecParameters(&secPrivateKeyAttributes)

        var parameters = [kSecAttrKeyType: keyType.secAttrString,
                          kSecPrivateKeyAttrs: secPrivateKeyAttributes] as [String: Any]
        if let authenticationContext = authenticationContext {
            parameters[kSecUseAuthenticationContext as String] = authenticationContext
        }

        keyGenerationAttributes.insertIntoSecParameters(&parameters)

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(parameters as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return privateKey
    }

    /// Create a `SecKey` instance for a new private key.
    ///
    /// This method creates a new private key for the given key type which can be saved in the data protection keychain.
    /// The underlying method creates a private / public key pair but only returns the private key.
    ///
    /// - Important: You cannot use the instance returned by this function and save it in the legacy file based macOS keychains.
    /// Trying to do so will result in undefined behavior like being able to save the key but not being able to query it.
    ///
    /// See `SecKey.cpp` and related sources in the `Security.framework`.
    ///
    /// - Parameters:
    ///   - keyType: Key type of the SecKey to create.
    ///   - keyGenerationAttributes: General key generation attributes.
    ///   - privateKeyAttributes: Private key specific key generation attributes.
    ///
    /// - Returns: The newly generated private key.
    static func createSecKey(
        keyType: SecKeyType,
        keyGenerationAttributes: SecKeyAttributes,
        privateKeyAttributes: SecKeyAttributes
    ) throws -> SecKey {
        precondition(keyGenerationAttributes.keySizeInBits != nil, "Required key attribute 'keySizeInBits' for key generation missing.")

        var parameters = [kSecAttrKeyType: keyType.secAttrString,
                          kSecAttrIsPermanent: false] as [String: Any]

        var secPrivateKeyAttributes = [:] as [String: Any]
        privateKeyAttributes.insertIntoSecParameters(&secPrivateKeyAttributes)
        parameters[kSecPrivateKeyAttrs as String] = secPrivateKeyAttributes
        // Note that this availabilty check will succeed for macOS 10.15+
        // Also iOS 12 doesn't really need the kSecUseDataProtectionKeychain attribute since iOS only has one keychain type.
        if #available(iOS 13.0, *) {
            parameters[kSecUseDataProtectionKeychain as String] = true
        }

        keyGenerationAttributes.insertIntoSecParameters(&parameters)

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(parameters as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return privateKey
    }

    /// Create a legacy `SecKey` instance for a new private key.
    ///
    /// This method creates a new private key for the given key type which can be save in file based keychains in macOS.
    /// The underlying method creates a private / public key pair but only returns the private key.
    ///
    /// - Important: You cannot use the instance returned by this function and save it in the data protection keychain.
    /// Trying to do so will result in undefined behavior like being able to save the key but not being able to query it.
    ///
    /// See `SecKey.cpp` and related sources in the `Security.framework`.
    ///
    /// - Parameters:
    ///   - keyType: Key type of the SecKey to create.
    ///   - keyGenerationAttributes: General key generation attributes.
    ///   - privateKeyAttributes: Private key specific key generation attributes.
    ///
    /// - Returns: The newly generated private key.
    @available(iOS, unavailable)
    static func createLegacySecKey(
        keyType: SecKeyType,
        keyGenerationAttributes: SecKeyAttributes,
        privateKeyAttributes: SecKeyAttributes
    ) throws -> SecKey {
        precondition(keyGenerationAttributes.keySizeInBits != nil, "Required key attribute 'keySizeInBits' for key generation missing.")

        var parameters = [kSecAttrKeyType: keyType.secAttrString,
                          kSecAttrIsPermanent: false] as [String: Any]

        privateKeyAttributes.insertIntoSecParameters(&parameters)
        keyGenerationAttributes.insertIntoSecParameters(&parameters)

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(parameters as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return privateKey
    }
}

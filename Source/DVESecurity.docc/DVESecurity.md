# ``DVESecurity``

Secure your app data with cryptographic functions and by using keychains.

## Overview

The DVESecurity framework provides easy access to cryptographic and keychain functions for iOS and macOS.

The types and functions included in the framework provide high-level access to the functionality provided by the [Security](https://developer.apple.com/documentation/security) and [CommonCrypto](https://opensource.apple.com/source/CommonCrypto/) frameworks, abstracting and simplifying the necessary API calls for Swift based solutions.

## Topics

### Keychains
- <doc:Keychain-GettingStarted>
- ``Keychain``
- ``SecKeyAttributes``
- ``ConvertibleToSecKey``
- ``CreateableFromSecKey``
- ``DefinesSecKeyClass``
- ``SecKeyClass``
- ``SecKeyType``
- ``SecKeyConvertible``
- ``KeychainError``

### Cryptography
- ``Crypto``
- ``RSAKey``
- ``RSAPrivateKey``
- ``RSAPublicKey``
- ``ECCKey``
- ``ECCPrivateKey``
- ``ECCPublicKey``
- ``ECCSecureEnclaveKey``
- ``CCHmacAlgorithmMapping``
- ``CommonCryptoError``
- ``CryptoError``

### Hashing
- ``Hashing``
- ``HashFunction``

### Application Entitlements
- ``AppEntitlements``

### ASN.1 Coding
- ``ASN1``

### Errors
- ``AppEntitlementsError``
- ``CodeSignatureError``

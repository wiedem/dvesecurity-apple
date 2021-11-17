# ``DVESecurity``

Secure your app data with cryptographic functions and by using keychains.

## Overview

Use the DVESecurity framework for easy access to iOS and macOS cryptographic and keychain features.
The framework provides easy access to functionalities provided by the [Security](https://developer.apple.com/documentation/security) and [CommonCrypto](https://opensource.apple.com/source/CommonCrypto/) frameworks, abstracting and simplifying the necessary API calls for Swift based solutions.

## Topics

### Keychains
- <doc:Keychain-GettingStarted>
- ``Keychain``
- ``Keychain/Legacy``
- ``SecKeyAttributes``
- ``ConvertibleToSecKey``
- ``CreateableFromSecKey``
- ``DefinesSecKeyClass``
- ``SecKeyClass``
- ``SecKeyType``
- ``SecKeyConvertible``
- ``KeychainError``

### Cryptography
- <doc:Crypto-GettingStarted>
- ``Crypto``
- ``SymmetricKey``
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

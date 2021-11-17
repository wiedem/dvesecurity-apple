# ``DVESecurity/Crypto``

## Overview

This container provides symmetric and asymmetric cryptographic methods and types.

Provided that RSA and iOS 12 support are not an issue, Apple's [CryptoKit](https://developer.apple.com/documentation/cryptokit) framework can alternatively be used for the same functionality.

- Note: The use of encryption in applications requires compliance with export regulations. See [Complying with Encryption Export Regulations](https://developer.apple.com/documentation/security/complying_with_encryption_export_regulations) for further details.

## Topics

### Cryptographic Methods
- ``Crypto/AES``
- ``Crypto/RSA``
- ``Crypto/ECC``

### Password Creation
- ``Crypto/createRandomPassword(length:characters:)``
- ``Crypto/defaultRandomPasswordAlphabet``
- ``Crypto/createRandomData(length:)``

### Message Authentication Codes
- ``Crypto/HMAC``

### Errors
- ``Crypto/KeyError``
- ``Crypto/AESError``
- ``Crypto/AsymmetricCryptoError``
- ``Crypto/RSAError``

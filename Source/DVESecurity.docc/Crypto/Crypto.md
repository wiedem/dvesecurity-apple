# ``DVESecurity/Crypto``

## Overview

This container provides symmetric and asymmetric cryptographic methods and types.

Supported cryptographic methods are AES, RSA and ECC.
The cryptographic key types are compatible with the [Apple CryptoKit](https://developer.apple.com/documentation/cryptokit).

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

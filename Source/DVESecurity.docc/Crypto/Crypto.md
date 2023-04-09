# ``DVESecurity/Crypto``

## Overview

This container provides symmetric and asymmetric cryptographic methods and types.

Supported cryptographic methods are AES, RSA and ECC.
The cryptographic key types and operations are compatible with the [Apple CryptoKit](https://developer.apple.com/documentation/cryptokit).

When dealing with cryptographic keys, additional security measures should be taken with regard to memory management.
Secure key types should implement the ``SecureData`` protocol, with ``Crypto/KeyData`` there is an implementation for this purpose.

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

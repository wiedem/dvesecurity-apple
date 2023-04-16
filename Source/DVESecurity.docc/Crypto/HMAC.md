# ``DVESecurity/Crypto/HMAC``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

## Overview
HMACs (Hash-Based Message Authentication Codes) can be used for cryptographic authentication and verification of data.

Use HMACs to protect data against tampering and verify its authenticity using a symmetric key. They are an alternative to digital signing and verification with public key cryptography.

### Creating and Verifying Authentication Codes
HMACs require a secret symmetric key, which can be generated e.g. with ``Crypto/KeyData/createRandomData(length:)``. Alternatively, the HMAC implementations also directly support the use of the ``Crypto/AES/Key`` type.

As hash functions all types can be used that fulfill the ``HashFunction`` and ``CCHmacAlgorithmMapping`` protocols, such as the ``Hashing/SHA256`` type.

```swift
let securedData = "My message".data(using: .utf8)!
let keyData = try Crypto.KeyData.createRandomData(length: 32)

// Generate the signature data that can be sent to a recipient with the plain text.
let authenticationCode = Crypto.HMAC<Hashing.SHA256>.authenticationCode(for: securedData, keyData: keyData)

// The recipient can check the plaintext data with the signature data using the same secret key.
let isCodeValid = Crypto.HMAC<Hashing.SHA256>.isValidAuthenticationCode(authenticationCode, authenticating: securedData, keyData: keyData)
```
```swift
let securedData = "My message".data(using: .utf8)!
let key = try Crypto.AES.Key.createRandom(.bits256)

let authenticationCode = Crypto.HMAC<Hashing.SHA256>.authenticationCode(for: securedData, key: key)

let isCodeValid = Crypto.HMAC<Hashing.SHA256>.isValidAuthenticationCode(authenticationCode, authenticating: securedData, key: key)
```

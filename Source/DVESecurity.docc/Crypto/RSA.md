# ``DVESecurity/Crypto/RSA``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

## Overview
RSA is commonly used for symmetric key encryption and message signing.

Plaintext messages that are to be encrypted by RSA must have a fixed size.
To encrypt messages of any size, RSA is usually combined with other hashing, padding, and symmetric encryption algorithms.

For a list of available algorithms and their limitations see ``EncryptionAlgorithm``.

### Key Generation
A RSA private key is required to decrypt and sign data:

```swift
let rsaPrivateKey = try Crypto.RSA.PrivateKey(bitCount: 2048)
```

For secure storage of private RSA keys, iOS and macOS keychains can be used.
```swift
try Keychain.saveKey(rsaPrivateKey, withTag: "RSA Private Key Tag")
```
See ``Keychain`` for more details on how to save RSA keys.


The public key for encrypting and validating signatures can be directly generated from the private key:

```swift
let rsaPublicKey = rsaPrivateKey.publicKey()
```

### Encryption & Decryption
Various algorithms are available for encrypting data with RSA. For decryption, the same algorithm must be used that was used for encryption.

Note that different algorithms may have different maximum message sizes. The maximum size of a message can be determined via ``EncryptionAlgorithm/maxPlainTextLength(for:)``.

If an attempt is made to encrypt a message with an invalid size, an ``Crypto/RSAError/invalidDataLength`` error is thrown.

```swift
let plainTextData = "Hello World!".data(using: .utf8)!
let cipherTextData = try rsaPublicKey.encrypt(plainTextData, using: .oaepSHA256)

let decryptedData = try rsaPrivateKey.decrypt(cipherTextData, using: .oaepSHA256)
```

### Signing and Validation of Signatures
Cryptographic signatures of messages with RSA are formed using hashing functions.
The available signature algorithms are defined in the ``MessageSignatureAlgorithm`` enum.

```swift
let plainTextData = "Hello World!".data(using: .utf8)!

let signatureData = try rsaPrivateKey.signature(for: plainTextData, algorithm: .pssSHA256)
let isValid = try rsaPublicKey.isValidSignature(signatureData, of: plainTextData, algorithm: .pssSHA256)
```

In special scenarios, the digest data from a hashing function can also be signed directly:
```swift
let plainTextData = "Hello World!".data(using: .utf8)!

let digest = Hashing.SHA256.hash(plainTextData)

let signatureData = try rsaPrivateKey.digestSignature(for: digest, algorithm: .pssSHA256)
let isValid = try rsaPublicKey.isValidDigestSignature(signatureData, digest: digest, algorithm: .pssSHA256)
```

Note that the signature algorithm used must match the hashing function used.
See ``DigestSignatureAlgorithm``.

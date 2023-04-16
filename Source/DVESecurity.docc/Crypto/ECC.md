# ``DVESecurity/Crypto/ECC``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

## Overview
ECC is a modern alternative to RSA that can be used for symmetric key encryption and message signing.

### Key Generation
An ECC private key is required to decrypt and sign data:

```swift
let privateKey = Crypto.ECC.PrivateKey(curve: .p192)
```

The public key for encrypting and validating signatures can be directly generated from the private key:

```swift
let publicKey: Crypto.ECC.PublicKey = privateKey.publicKey()
```

#### Secure Enclave Keys
ECC keys can also be created using the [Secure Enclave](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/protecting_keys_with_the_secure_enclave):

```swift
let secureEnclaveKey = try Crypto.ECC.SecureEnclaveKey()
let publicKey: Crypto.ECC.PublicKey = secureEnclaveKey.publicKey()
```

### Encryption & Decryption
Supported hybrid ECIES encryption or decryption algorithm are defined in ``EncryptionAlgorithm``.
They allow encryption of plaintext messages of arbitrary length.

```swift
let plainTextData = "Hello World!".data(using: .utf8)!
let cipherTextData = try publicKey.encrypt(plainTextData, using: .eciesStandardVariableIVX963SHA256AESGCM)

let decryptedData = try privateKey.decrypt(cipherTextData, using: .eciesStandardVariableIVX963SHA256AESGCM)
```

### Signing and Validation of Signatures
Supported ECC message signature algorithms are defined in ``SignatureAlgorithm``.

```swift
let plainTextData = "Hello World!".data(using: .utf8)!

let signatureData = try privateKey.signature(for: plainTextData, algorithm: .ecdsaX962SHA256)
let isValid = try publicKey.isValidSignature(signatureData, for: plainTextData, algorithm: .ecdsaX962SHA256)
```

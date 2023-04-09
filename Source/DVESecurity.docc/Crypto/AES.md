# ``DVESecurity/Crypto/AES``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

## Overview
AES can be used for symmetric encryption of data of any length with a symmetric key.

### Key Generation
Encrypting data with AES requires an initialization vector and a symmetric key.

Initialization vectors don't need to be kept secret but must be random and should not be re-used for the same key.
The ``createInitVector()`` method creates a new random initialization vector which can be used to encrypt a plain text message.

Secure symmetric keys should be generated from random data or derived from passwords or passphrases.
One method for this is provided by ``DVESecurity/Crypto/AES/Key/init(keySize:password:withSalt:pseudoRandomAlgorithm:rounds:)`` initializer.

```swift
let initVector = try Crypto.AES.createInitVector()
let aesKey = try Crypto.AES.Key(
  keySize: .bits192,
  password: "Password",
  withSalt: "Salt",
  pseudoRandomAlgorithm: .hmacAlgSHA256,
  rounds: 10000
)
```

For secure storage of symmetric AES keys, iOS and macOS keychains can be used.
```swift
try Keychain.saveKey(aesKey, withTag: "KeyTag", applicationLabel: "ApplicationLabel")
```
See ``Keychain`` for more details on how to save symmetric keys.

### Encryption
Encryption with AES can either be done directly with the key ``Key/encrypt(_:initVector:)`` or the  ``encrypt(_:withKey:initVector:)-2m6jq`` and ``encrypt(_:withKey:initVector:)-1p0o7`` methods:
```swift
let plainText = "Secret Message".data(using: .utf8)!

let encryptedData1 = try aesKey.encrypt(plainText, initVector: initVector)
// ... which is equivalent to ...
let encryptedData2 = try Crypto.AES.encrypt(plainText, withKey: aesKey, initVector: initVector)
```

### Decryption
To decrypt data encrypted with AES, use the ``Key/decrypt(_:initVector:)`` method on the key or the ``decrypt(_:withKey:initVector:)-1qtvr`` and ``decrypt(_:withKey:initVector:)-3m53z`` method:
```swift
let plainText1 = try aesKey.decrypt(encryptedData, initVector: initVector)
// ... which is equivalent to ...
let plainText2 = Crypto.AES.decrypt(encryptedData, withKey: aesKey, initVector: initVector)
```

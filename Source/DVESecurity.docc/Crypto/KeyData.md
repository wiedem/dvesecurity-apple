# ``DVESecurity/Crypto/KeyData``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

### Keychain
Various keychain operations, such as retrieving symmetric keys, may return a `KeyData` instance.
These keys can then be used directly by the corresponding cryptographic methods, such as AES methods in the ``Crypto/AES`` container.

```swift
if let keyData: Crypto.KeyData = try Keychain.queryKey(withTag: "KeyTag", applicationLabel: nil) {
    let plainText = try Crypto.AES.decrypt(data, withKey: keyData, initVector: initVector)
}
```

In general, for symmetric keys there is the more convenient method of using the ``AES/Key`` type, with which the corresponding methods can be called directly:

```swift
if let key: Crypto.AES.Key = try Keychain.queryKey(withTag: "KeyTag", applicationLabel: nil) {
    let plainText = try key.decrypt(data, initVector: initVector)
}
```

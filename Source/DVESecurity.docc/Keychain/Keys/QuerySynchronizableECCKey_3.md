# ``DVESecurity/Keychain/querySynchronizableKey(for:withTag:accessGroup:)-6hfzy``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

- Note: This method uses the SHA-1 of the public key to find the corresponding private key in the keychain.

The following example shows how you can query a private key of type ``Crypto/ECC/PrivateKey`` from the keychain and the default keychain access group.
```swift
let privateKey: Crypto.ECC.PrivateKey? = try Keychain.querySynchronizableKey(for: publicKey)
```

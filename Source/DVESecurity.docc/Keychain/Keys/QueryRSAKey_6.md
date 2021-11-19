# ``DVESecurity/Keychain/queryKey(for:withTag:accessGroup:authentication:)-8h63r``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

- Note: This method uses the SHA-1 of the public key to find the corresponding private key in the keychain.

The following example shows how you can query a private key of type ``Crypto/RSA/PrivateKey`` from the keychain and the default keychain access group.
```swift
let privateKey: Crypto.RSA.PrivateKey? = try Keychain.queryKey(for: publicKey)
```

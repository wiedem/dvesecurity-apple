# ``DVESecurity/Keychain/queryKey(withTag:accessGroup:authentication:)-52xe5``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

- Note: This method uses the SHA-1 of the public key to find the corresponding privte key in the keychain.

The following example shows how you can query a private key of type ``Crypto/RSA/PrivateKey`` from the keychain and the default keychain access group.
```swift
let privateKey: Crypto.RSA.PrivateKey? = try Keychain.queryKey(for: publicKey)
```

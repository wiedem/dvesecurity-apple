# ``Keychain/queryKey(withTag:accessGroup:authentication:)-5l8ir``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

- Important: If you do not specify a `tag` for the query and more than one private key exists for the specified public key in the access group the error
``KeychainError/ambiguousQueryResult`` will be thrown.

- Note: This method uses the SHA-1 of the public key to find the corresponding privte key in the keychain.

The following example shows how you can query a private key of type ``Crypto/ECC/PrivateKey`` from the keychain and the default keychain access group.
```swift
let privateKey: Crypto.ECC.PrivateKey? = try Keychain.ECC.queryKey(for: publicKey)
```

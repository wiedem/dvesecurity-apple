# ``DVESecurity/Keychain/querySynchronizableKey(for:withTag:accessGroup:completion:)-1can0``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

- Note: If you do not specify a `tag` for the query and more than one private key exists for the specified public key in the access group the error ``KeychainError/ambiguousQueryResult`` is returned as a result.

- Note: This method uses the SHA-1 of the public key to find the corresponding private key in the keychain.

The following example shows how you can query a private key of type ``RSAPrivateKey`` from the keychain and the default keychain access group.
```swift
Keychain.querySynchronizableKey(for: publicKey) { (result: Result<Crypto.RSA.PrivateKey?, Error>) in
    do {
        let key = try result.get()
    } catch {
        // Error handling
    }
}
```

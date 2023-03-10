# ``DVESecurity/Keychain/queryKey(for:withTag:accessGroup:authentication:completion:)-2jtnq``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

- Note: If you do not specify a `tag` for the query and more than one private key exists for the specified public key in the access group the error ``KeychainError/ambiguousQueryResult`` is returned as a result. Use a `tag` value if needed to make the query unique.

- Note: This method uses the SHA-1 of the public key to find the corresponding private key in the keychain.

The following example shows how you can query a private key type implementing the ``ECCPrivateKey`` protocol from the keychain and the default keychain access group.
```swift
Keychain.queryKey(for: publicKey) { (result: Result<Crypto.ECC.PrivateKey?, Error>) in
    do {
        let key = try result.get()
    } catch {
        // Error handling
    }
}
```

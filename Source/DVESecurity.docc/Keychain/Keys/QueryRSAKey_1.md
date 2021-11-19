# ``DVESecurity/Keychain/queryKey(withTag:accessGroup:authentication:completion:)-8x8b9``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

- Note: If multiple private keys exist for the specified tag in the access group the error ``KeychainError/ambiguousQueryResult`` is returned as a result. Make sure to use a unique `tag` value when storing a key or combine the search with the SHA1 of the public key.

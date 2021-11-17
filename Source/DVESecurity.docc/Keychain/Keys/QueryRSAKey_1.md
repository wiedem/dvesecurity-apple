# ``DVESecurity/Keychain/queryKey(for:withTag:accessGroup:authentication:completion:)-628z0``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

- Important: If you do not specify a `tag` for the query and more than one private key exists for the specified public key in the access group the error ``KeychainError/ambiguousQueryResult`` will be returned.

- Note: This method uses the SHA-1 of the public key to find the corresponding private key in the keychain.

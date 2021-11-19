# ``DVESecurity/Keychain/querySynchronizableKey(for:withTag:accessGroup:completion:)-6hfzy``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

- Note: If you do not specify a `tag` for the query and more than one private key exists for the specified public key in the access group the error ``KeychainError/ambiguousQueryResult`` will be returned.

- Note: This method uses the SHA-1 of the public key to find the corresponding private key in the keychain.

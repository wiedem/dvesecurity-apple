# ``DVESecurity/Keychain/queryKey(withTag:accessGroup:authentication:completion:)-976xd``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

- Attention: Make sure you use unique `tag` values for Secure Enclave and regular ECC keys.
Saving a Secure Enclave ECC key and a regular ECC key with the same tag may cause undefined behavior when trying to query or delete a key with the same `tag` value.

- Note: If multiple private keys exist for the specified tag in the access group the error ``KeychainError/ambiguousQueryResult`` is returned as a result. Make sure to use a unique `tag` value when storing a key or combine the search with the SHA1 of the public key.

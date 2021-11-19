# ``DVESecurity/Keychain/queryKey(withTag:accessGroup:authentication:)-5l8ir``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

- Attention: Make sure you use unique tag values for Secure Enclave and regular ECC keys.
Saving a Secure Enclave ECC key and a regular ECC key with the same tag may cause undefined behavior when trying to query or delete a key via this tag.

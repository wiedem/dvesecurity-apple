# ``DVESecurity/Keychain/saveSynchronizableKey(_:withTag:accessGroup:accessibility:label:)-7obmr``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

- Attention: Make sure you use unique `tag` values for Secure Enclave and regular ECC keys.
Saving a Secure Enclave ECC key and a regular ECC key with the same tag may cause undefined behavior when trying to query or delete a key via this tag.

To query the saved key from the keychain, you must specify the same `tag`  value and `accessGroup`  that was used when saving.

The `accessControl` parameter restricts the conditions under which an app can query the item, see ``Keychain/AccessControl`` for more details.

- Note: Make sure that you use a unique `tag` value for the key. If multiple private keys with the same tag are stored in the access group, trying to query a single entry with this tag will result in a ``KeychainError/ambiguousQueryResult`` error. 

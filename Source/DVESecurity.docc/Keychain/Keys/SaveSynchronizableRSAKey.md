# ``DVESecurity/Keychain/saveSynchronizableKey(_:withTag:accessGroup:accessibility:label:)-8inbq``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

To query the saved key from the keychain, you must specify the same `tag`  value and `accessGroup`  that was used when saving.

The `accessControl` parameter restricts the conditions under which an app can query the item, see ``Keychain/AccessControl`` for more details.

- Note: Make sure that you use a unique `tag` value for the key. If multiple private keys with the same tag are stored in the access group, trying to query a single entry with this tag will result in a ``KeychainError/ambiguousQueryResult`` error. 

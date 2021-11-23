# ``DVESecurity/Keychain/InternetPassword/queryOneSynchronizable(forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:)``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

Since all fields except the `account` are optional, you must ensure that the specified combination of fields identifies a unique entry.

Use one of the `queryItems` methods and filter the results with the ``Keychain/InternetPassword/Item/synchronizable`` field if you want to use a query which may return multiple items.

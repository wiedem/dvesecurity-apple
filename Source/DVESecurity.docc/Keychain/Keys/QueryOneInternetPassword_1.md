# ``DVESecurity/Keychain/InternetPassword/queryOne(forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:authentication:completion:)``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

Since all fields except the `account` are optional, you must ensure that the specified combination of fields identifies a unique entry.
If the query returns more than one item a ``KeychainError/ambiguousQueryResult`` error result will be returned.

Use one of the `queryItems` methods if you want to use a query which may return multiple items.

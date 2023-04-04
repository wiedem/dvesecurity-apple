# ``DVESecurity/ASN1/X509/SubjectPublicKeyInfo``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

## ASN.1 Syntax
The ASN.1 syntax of a public key info as defined in [RFC5912](https://tools.ietf.org/html/rfc5912):
```
SubjectPublicKeyInfo  ::=  SEQUENCE  {
     algorithm         AlgorithmIdentifier,
     subjectPublicKey  BIT STRING
}

AlgorithmIdentifier  ::=  SEQUENCE  {
     algorithm   OBJECT IDENTIFIER,
     parameters  ANY DEFINED BY algorithm OPTIONAL
}
```

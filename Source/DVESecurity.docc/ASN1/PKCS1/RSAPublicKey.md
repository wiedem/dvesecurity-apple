# ``DVESecurity/ASN1/PKCS1/RSAPublicKey``

@Metadata {
    @DocumentationExtension(mergeBehavior: append)
}

## ASN.1 Syntax
The ASN.1 syntax of the key representation is defined in [PKCS #1 v2.2 Appendix A.1.1](https://tools.ietf.org/html/rfc8017#appendix-A.1.1):
```
RSAPublicKey  ::=  SEQUENCE  {
    modulus          INTEGER, -- n
    publicExponent   INTEGER  -- e
}
```

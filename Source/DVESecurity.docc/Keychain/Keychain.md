# ``DVESecurity/Keychain``

## Overview

This container contains types and functions for the Data Protection Keychain of iOS and macOS.

Use the functionality provided in the ``Legacy`` container for file based keychains of macOS.

- Note: Trying to use the methods for the Data Protection Keychain in macOS applications without an application ID will cause your  app to crash with a fatal error.
Such macOS applications do not have access to the Data Protection Keychain.

## Topics

### Generic Queries
- ``Keychain/deleteAllItems(ofClass:inAccessGroup:)``
- ``Keychain/deleteAllItems(ofClass:inAccessGroups:)``
- ``Keychain/ItemClass``

### Query Authentication and Accessibility
- ``Keychain/AccessControl``
- ``Keychain/AccessControlFlags``
- ``Keychain/AccessControlFlag``
- ``Keychain/QueryAuthentication``
- ``Keychain/AuthenticationUI``

- ``Keychain/ItemAccessibility``
- ``Keychain/SynchronizableItemAccessibility``

### Access Groups
- ``Keychain/defaultAccessGroup``
- ``Keychain/accessGroups``

### Passwords
- ``Keychain/InternetPassword``
- ``Keychain/GenericPassword``

- ``Keychain/InternetPasswordError``
- ``Keychain/GenericPasswordError``

### RSA Keys
- ``Keychain/saveKey(_:withTag:accessGroup:accessControl:label:authenticationContext:)-3fhlv``
- ``Keychain/saveKeyPublisher(for:withTag:accessGroup:accessControl:authenticationContext:)-3qqba``

- ``Keychain/queryKey(withTag:accessGroup:authentication:completion:)-8x8b9``
- ``Keychain/queryKey(withTag:accessGroup:authentication:)-52xe5``
- ``Keychain/queryKey(withPublicKeySHA1:tag:accessGroup:authentication:completion:)-728dq``
- ``Keychain/queryKey(withPublicKeySHA1:tag:accessGroup:authentication:)-6sl8q``
- ``Keychain/queryKey(for:withTag:accessGroup:authentication:completion:)-628z0``
- ``Keychain/queryKey(for:withTag:accessGroup:authentication:)-8h63r``

- ``Keychain/queryKeyPublisher(withTag:accessGroup:authentication:)-2vh9v``
- ``Keychain/queryKeyPublisher(withPublicKeySHA1:tag:accessGroup:authentication:)-7yqa4``
- ``Keychain/queryKeyPublisher(for:withTag:accessGroup:authentication:)-6fzy1``

- ``Keychain/deleteKey(_:withTag:accessGroup:)-9g152``
- ``Keychain/deletePrivateKey(for:withTag:accessGroup:)-1akqe``
- ``Keychain/deleteKey(ofType:withTag:publicKeySHA1:accessGroup:)-bgct``

### Synchronizable RSA Keys
- ``Keychain/saveSynchronizableKey(_:withTag:accessGroup:accessibility:label:)-8inbq``

- ``Keychain/querySynchronizableKey(for:withTag:accessGroup:completion:)-1can0``
- ``Keychain/querySynchronizableKey(for:withTag:accessGroup:)-qk74``
- ``Keychain/querySynchronizableKey(withPublicKeySHA1:tag:accessGroup:completion:)-6rm2c``
- ``Keychain/querySynchronizableKey(withPublicKeySHA1:tag:accessGroup:)-93g5y``
- ``Keychain/querySynchronizableKey(withTag:accessGroup:completion:)-5i7el``
- ``Keychain/querySynchronizableKey(withTag:accessGroup:)-569jm``

- ``Keychain/deleteSynchronizableKey(_:withTag:accessGroup:)-58t34``
- ``Keychain/deleteSynchronizablePrivateKey(for:withTag:accessGroup:)-823ri``
- ``Keychain/deleteSynchronizableKey(ofType:withTag:publicKeySHA1:accessGroup:)-8yqrn``

### ECC Keys
- ``Keychain/saveKey(_:withTag:accessGroup:accessControl:label:authenticationContext:)-9x3dp``
- ``Keychain/saveKeyPublisher(for:withTag:accessGroup:accessControl:authenticationContext:)-1m2ot``

- ``Keychain/queryKey(withTag:accessGroup:authentication:completion:)-976xd``
- ``Keychain/queryKey(withTag:accessGroup:authentication:)-5l8ir``
- ``Keychain/queryKey(withPublicKeySHA1:tag:accessGroup:authentication:completion:)-64my6``
- ``Keychain/queryKey(withPublicKeySHA1:tag:accessGroup:authentication:)-7e2vn``
- ``Keychain/queryKey(for:withTag:accessGroup:authentication:completion:)-2jtnq``
- ``Keychain/queryKey(for:withTag:accessGroup:authentication:)-9zkq7``

- ``Keychain/queryKeyPublisher(withTag:accessGroup:authentication:)-86a01``
- ``Keychain/queryKeyPublisher(withPublicKeySHA1:tag:accessGroup:authentication:)-74k20``
- ``Keychain/queryKeyPublisher(for:withTag:accessGroup:authentication:)-632gz``

- ``Keychain/deleteKey(ofType:withTag:publicKeySHA1:accessGroup:)-7jjm5``
- ``Keychain/deletePrivateKey(for:withTag:accessGroup:)-3y5ru``
- ``Keychain/deleteKey(_:withTag:accessGroup:)-85kya``

### Synchronizable ECC Keys
- ``Keychain/saveSynchronizableKey(_:withTag:accessGroup:accessibility:label:)-7obmr``

- ``Keychain/querySynchronizableKey(withPublicKeySHA1:tag:accessGroup:completion:)-4cgih``
- ``Keychain/querySynchronizableKey(withPublicKeySHA1:tag:accessGroup:)-995vh``
- ``Keychain/querySynchronizableKey(withTag:accessGroup:completion:)-ohxr``
- ``Keychain/querySynchronizableKey(withTag:accessGroup:)-7dnen``
- ``Keychain/querySynchronizableKey(for:withTag:accessGroup:completion:)-qqh6``
- ``Keychain/querySynchronizableKey(for:withTag:accessGroup:)-6hfzy``

- ``Keychain/deleteSynchronizableKey(_:withTag:accessGroup:)-7s2wz``
- ``Keychain/deleteSynchronizablePrivateKey(for:withTag:accessGroup:)-6js1n``
- ``Keychain/deleteSynchronizableKey(ofType:withTag:publicKeySHA1:accessGroup:)-k4pw``

### Symmetric Keys
- ``Keychain/saveKey(_:withTag:applicationLabel:accessGroup:accessControl:label:authenticationContext:)``
- ``Keychain/saveKeyPublisher(for:withTag:applicationLabel:accessGroup:accessControl:authenticationContext:)``

- ``Keychain/updateKey(newKey:withTag:applicationLabel:accessGroup:authentication:)``

- ``Keychain/queryKey(withTag:applicationLabel:accessGroup:authentication:completion:)``
- ``Keychain/queryKey(withTag:applicationLabel:accessGroup:authentication:)``

- ``Keychain/queryKeyPublisher(withTag:applicationLabel:accessGroup:authentication:)``

- ``Keychain/deleteKey(withTag:applicationLabel:accessGroup:)``

### Synchronizable Symmetric Keys
- ``Keychain/saveSynchronizableKey(_:withTag:applicationLabel:accessGroup:accessibility:label:)``

- ``Keychain/updateSynchronizableKey(newKey:withTag:applicationLabel:accessGroup:)``

- ``Keychain/querySynchronizableKey(withTag:applicationLabel:accessGroup:completion:)``
- ``Keychain/querySynchronizableKey(withTag:applicationLabel:accessGroup:)``

- ``Keychain/deleteSynchronizableKey(withTag:applicationLabel:accessGroup:)``

### Secure Enclave Keys
- ``Keychain/saveKey(_:withTag:accessGroup:accessControl:label:authenticationContext:)-7i21q``
- ``Keychain/queryKey(withTag:accessGroup:authentication:completion:)-8ssls``
- ``Keychain/queryKey(withTag:accessGroup:authentication:)-54te0``
- ``Keychain/queryKey(withPublicKeySHA1:tag:accessGroup:authentication:)-9dffr``
- ``Keychain/queryKey(for:withTag:accessGroup:authentication:)-65j90``

- ``Keychain/queryKeyPublisher(withTag:accessGroup:authentication:)-76gyy``

- ``Keychain/deleteSecureEnclaveKey(withTag:accessGroup:)``

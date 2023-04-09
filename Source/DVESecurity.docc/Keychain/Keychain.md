# ``DVESecurity/Keychain``

## Overview

This container contains types and functions for the Data Protection Keychain of iOS and macOS.

Use the functionality provided in the ``Legacy`` container for file based keychains of macOS.

- Note: Trying to use the methods for the Data Protection Keychain in macOS applications without an application ID will cause your app to crash with a fatal error.
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

- ``Keychain/queryKey(withTag:accessGroup:authentication:completion:)-8x8b9``
- ``Keychain/queryKey(withTag:accessGroup:authentication:)-52xe5``
- ``Keychain/queryKey(withPublicKeySHA1:tag:accessGroup:authentication:completion:)-728dq``
- ``Keychain/queryKey(withPublicKeySHA1:tag:accessGroup:authentication:)-6sl8q``
- ``Keychain/queryKey(for:withTag:accessGroup:authentication:completion:)-5ay1v``
- ``Keychain/queryKey(for:withTag:accessGroup:authentication:)-3mmy8``

- ``Keychain/deleteKey(_:withTag:accessGroup:)-9g152``
- ``Keychain/deletePrivateKey(for:withTag:accessGroup:)-1akqe``
- ``Keychain/deleteKey(ofType:withTag:publicKeySHA1:accessGroup:)-bgct``

### Synchronizable RSA Keys
- ``Keychain/saveSynchronizableKey(_:withTag:accessGroup:accessibility:label:)-8inbq``

- ``Keychain/querySynchronizableKey(withTag:accessGroup:completion:)-5i7el``
- ``Keychain/querySynchronizableKey(withTag:accessGroup:)-569jm``
- ``Keychain/querySynchronizableKey(withPublicKeySHA1:tag:accessGroup:completion:)-6rm2c``
- ``Keychain/querySynchronizableKey(withPublicKeySHA1:tag:accessGroup:)-93g5y``
- ``Keychain/querySynchronizableKey(for:withTag:accessGroup:completion:)-977un``
- ``Keychain/querySynchronizableKey(for:withTag:accessGroup:)-4awrb``

- ``Keychain/deleteSynchronizableKey(_:withTag:accessGroup:)-58t34``
- ``Keychain/deleteSynchronizablePrivateKey(for:withTag:accessGroup:)-823ri``
- ``Keychain/deleteSynchronizableKey(ofType:withTag:publicKeySHA1:accessGroup:)-8yqrn``

### ECC Keys
- ``Keychain/saveKey(_:withTag:accessGroup:accessControl:label:authenticationContext:)-9x3dp``

- ``Keychain/queryKey(withTag:accessGroup:authentication:completion:)-976xd``
- ``Keychain/queryKey(withTag:accessGroup:authentication:)-5l8ir``
- ``Keychain/queryKey(withPublicKeySHA1:tag:accessGroup:authentication:completion:)-64my6``
- ``Keychain/queryKey(withPublicKeySHA1:tag:accessGroup:authentication:)-7e2vn``
- ``Keychain/queryKey(for:withTag:accessGroup:authentication:completion:)-7pj8l``
- ``Keychain/queryKey(for:withTag:accessGroup:authentication:)-705cp``

- ``Keychain/deleteKey(ofType:withTag:publicKeySHA1:accessGroup:)-7jjm5``
- ``Keychain/deletePrivateKey(for:withTag:accessGroup:)-3y5ru``
- ``Keychain/deleteKey(_:withTag:accessGroup:)-85kya``

### Synchronizable ECC Keys
- ``Keychain/saveSynchronizableKey(_:withTag:accessGroup:accessibility:label:)-7obmr``

- ``Keychain/querySynchronizableKey(withTag:accessGroup:completion:)-ohxr``
- ``Keychain/querySynchronizableKey(withTag:accessGroup:)-7dnen``
- ``Keychain/querySynchronizableKey(withPublicKeySHA1:tag:accessGroup:completion:)-4cgih``
- ``Keychain/querySynchronizableKey(withPublicKeySHA1:tag:accessGroup:)-995vh``
- ``Keychain/querySynchronizableKey(for:withTag:accessGroup:completion:)-7t3by``
- ``Keychain/querySynchronizableKey(for:withTag:accessGroup:)-9s51u``

- ``Keychain/deleteSynchronizableKey(_:withTag:accessGroup:)-7s2wz``
- ``Keychain/deleteSynchronizablePrivateKey(for:withTag:accessGroup:)-6js1n``
- ``Keychain/deleteSynchronizableKey(ofType:withTag:publicKeySHA1:accessGroup:)-k4pw``

### Symmetric Keys
- ``Keychain/saveKey(_:withTag:applicationLabel:accessGroup:accessControl:label:authenticationContext:)-2f06e``
- ``Keychain/saveKey(_:withTag:applicationLabel:accessGroup:accessControl:label:authenticationContext:)-3syxw``

- ``Keychain/updateKey(newKey:withTag:applicationLabel:accessGroup:authentication:)-7dfa4``
- ``Keychain/updateKey(newKey:withTag:applicationLabel:accessGroup:authentication:)-5ibv3``


- ``Keychain/queryKey(withTag:applicationLabel:accessGroup:authentication:completion:)-6m7re``
- ``Keychain/queryKey(withTag:applicationLabel:accessGroup:authentication:completion:)-295i7``
- ``Keychain/queryKey(withTag:applicationLabel:accessGroup:authentication:)-1oxfn``
- ``Keychain/queryKey(withTag:applicationLabel:accessGroup:authentication:)-57zj2``
- ``Keychain/queryKey(withTag:applicationLabel:accessGroup:authentication:)-empy``
- ``Keychain/queryKey(withTag:applicationLabel:accessGroup:authentication:)-91veo``

- ``Keychain/deleteKey(withTag:applicationLabel:accessGroup:)``

### Synchronizable Symmetric Keys
- ``Keychain/saveSynchronizableKey(_:withTag:applicationLabel:accessGroup:accessibility:label:)-7jabm``
- ``Keychain/saveSynchronizableKey(_:withTag:applicationLabel:accessGroup:accessibility:label:)-1p88y``

- ``Keychain/updateSynchronizableKey(newKey:withTag:applicationLabel:accessGroup:)-89r83``
- ``Keychain/updateSynchronizableKey(newKey:withTag:applicationLabel:accessGroup:)-169l``

- ``Keychain/querySynchronizableKey(withTag:applicationLabel:accessGroup:completion:)-92ur9``
- ``Keychain/querySynchronizableKey(withTag:applicationLabel:accessGroup:completion:)-6nui1``
- ``Keychain/querySynchronizableKey(withTag:applicationLabel:accessGroup:)-3ir5g``
- ``Keychain/querySynchronizableKey(withTag:applicationLabel:accessGroup:)-81svh``
- ``Keychain/querySynchronizableKey(withTag:applicationLabel:accessGroup:)-8h97w``
- ``Keychain/querySynchronizableKey(withTag:applicationLabel:accessGroup:)-1jhkq``

- ``Keychain/deleteSynchronizableKey(withTag:applicationLabel:accessGroup:)``

### Secure Enclave Keys
- ``Keychain/saveKey(_:withTag:accessGroup:accessControl:label:authenticationContext:)-7i21q``
- ``Keychain/queryKey(withTag:accessGroup:authentication:completion:)-8ssls``
- ``Keychain/queryKey(withTag:accessGroup:authentication:)-54te0``
- ``Keychain/queryKey(withPublicKeySHA1:tag:accessGroup:authentication:)-9dffr``
- ``Keychain/queryKey(for:withTag:accessGroup:authentication:)-6xgjk``

- ``Keychain/deleteSecureEnclaveKey(withTag:accessGroup:)``

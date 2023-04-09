# ``DVESecurity/Keychain/GenericPassword``

## Overview

Generic password keychain entries are general entries that cannot be assigned to any of the other available keychain types.
This may include cryptographic key types not directly supported by the keychain.

The ``GenericPassword`` container provides methods to store and retrieve entries as `String` values or as arbitrary keys.

## Topics

### Retrieve Items
- ``query(forAccount:service:accessGroup:authentication:completion:)``
- ``query(forAccount:service:accessGroup:authentication:)``

- ``queryKey(forAccount:service:accessGroup:authentication:completion:)-78h4l``
- ``queryKey(forAccount:service:accessGroup:authentication:completion:)-36nsf``
- ``queryKey(forAccount:service:accessGroup:authentication:)-8xcrt``

- ``queryItems(account:service:accessGroup:authentication:completion:)``
- ``queryItems(account:service:accessGroup:authentication:)``

### Save and Update Items
- ``save(_:forAccount:service:accessGroup:accessControl:label:authenticationContext:)``
- ``saveKey(_:forAccount:service:accessGroup:accessControl:label:authenticationContext:)-1wljc``
- ``saveKey(_:forAccount:service:accessGroup:accessControl:label:authenticationContext:)-rtem``

- ``upsert(_:forAccount:service:accessGroup:accessControl:label:authentication:)``

- ``update(newPassword:forAccount:service:accessGroup:authentication:)``

### Delete Items
- ``delete(forAccount:service:accessGroup:)``

### Retrieve Synchronizable Items
- ``querySynchronizable(forAccount:service:accessGroup:completion:)``
- ``querySynchronizable(forAccount:service:accessGroup:)``

- ``querySynchronizableKey(forAccount:service:accessGroup:completion:)``
- ``querySynchronizableKey(forAccount:service:accessGroup:)-2k62m``
- ``querySynchronizableKey(forAccount:service:accessGroup:)-63123``

### Save and Update Synchronizable Items
- ``saveSynchronizable(_:forAccount:service:accessGroup:accessibility:label:)``

- ``saveSynchronizableKey(_:forAccount:service:accessGroup:accessibility:label:)-86tf8``
- ``saveSynchronizableKey(_:forAccount:service:accessGroup:accessibility:label:)-98nyp``

- ``upsertSynchronizable(_:forAccount:service:accessGroup:accessibility:label:)``

- ``updateSynchronizable(newPassword:forAccount:service:accessGroup:)``

### Delete Synchronizable Items
- ``deleteSynchronizable(forAccount:service:accessGroup:)``

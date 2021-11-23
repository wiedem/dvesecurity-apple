# ``DVESecurity/Keychain/GenericPassword``

## Overview

Generic password keychain entries are general entries that cannot be assigned to any of the other available keychain types. This may include cryptographic key types not directly supported by the keychain.

The ``GenericPassword`` container provides methods to store and retrieve entries as `String` values or as arbitrary keys conforming to the ``RawKeyConvertible`` protocol.

- Note: Due to an issue / limitation in iOS 12, the synchronous query methods are only available for iOS 13 and later.
With iOS 12 a synchronous query on the main thread leads to a deadlock when the keychain services try to display a UI due to an access control restriction.

## Topics

### Retrieve Items
- ``query(forAccount:service:accessGroup:authentication:completion:)``
- ``query(forAccount:service:accessGroup:authentication:)``

- ``queryKey(forAccount:service:accessGroup:authentication:completion:)``
- ``queryKey(forAccount:service:accessGroup:authentication:)``

- ``queryItems(account:service:accessGroup:authentication:completion:)``
- ``queryItems(account:service:accessGroup:authentication:)``

### Save and Update Items
- ``save(_:forAccount:service:accessGroup:accessControl:label:authenticationContext:)``
- ``saveKey(_:forAccount:service:accessGroup:accessControl:label:authenticationContext:)``

- ``upsert(_:forAccount:service:accessGroup:accessControl:label:authentication:)``

- ``update(newPassword:forAccount:service:accessGroup:authentication:)``

### Delete Items
- ``delete(forAccount:service:accessGroup:)``

### Retrieve Synchronizable Items
- ``querySynchronizable(forAccount:service:accessGroup:completion:)``
- ``querySynchronizable(forAccount:service:accessGroup:)``

- ``querySynchronizableKey(forAccount:service:accessGroup:completion:)``
- ``querySynchronizableKey(forAccount:service:accessGroup:)``

### Save and Update Synchronizable Items
- ``saveSynchronizable(_:forAccount:service:accessGroup:accessibility:label:)``
- ``saveSynchronizableKey(_:forAccount:service:accessGroup:accessibility:label:)``

- ``upsertSynchronizable(_:forAccount:service:accessGroup:accessibility:label:)``

- ``updateSynchronizable(newPassword:forAccount:service:accessGroup:)``

### Delete Synchronizable Items
- ``deleteSynchronizable(forAccount:service:accessGroup:)``

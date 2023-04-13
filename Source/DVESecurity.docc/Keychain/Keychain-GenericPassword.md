# ``DVESecurity/Keychain/GenericPassword``

## Overview

Generic password keychain entries are general entries that cannot be assigned to any of the other available keychain types.
This may include cryptographic key types not directly supported by the keychain.

The ``GenericPassword`` container provides methods to store and retrieve entries as `String` values or as arbitrary keys.

```swift
try Keychain.GenericPassword.save("MySecret", forAccount: "MyAccount", service: "MyService")

let secret = try Keychain.GenericPassword.query(forAccount: "MyAccount", service: "MyService")
```

## Topics

### Retrieve Items
- ``query(forAccount:service:accessGroup:authentication:completion:)``
- ``query(forAccount:service:accessGroup:authentication:)-80gfa``

- ``queryKey(forAccount:service:accessGroup:authentication:completion:)-6ydyv``
- ``queryKey(forAccount:service:accessGroup:authentication:completion:)-bjm8``
- ``queryKey(forAccount:service:accessGroup:authentication:)-3m6bw``
- ``queryKey(forAccount:service:accessGroup:authentication:)-7zkns``

- ``queryItems(account:service:accessGroup:authentication:completion:)``
- ``queryItems(account:service:accessGroup:authentication:)-12mi8``
- ``queryItems(account:service:accessGroup:authentication:)-qmeo``

### Save and Update Items
- ``save(_:forAccount:service:accessGroup:accessControl:label:authenticationContext:)``
- ``saveKey(_:forAccount:service:accessGroup:accessControl:label:authenticationContext:)-7iy3b``
- ``saveKey(_:forAccount:service:accessGroup:accessControl:label:authenticationContext:)-2truy``

- ``upsert(_:forAccount:service:accessGroup:accessControl:label:authentication:)``

- ``update(newPassword:forAccount:service:accessGroup:authentication:)``

### Delete Items
- ``delete(forAccount:service:accessGroup:)``

### Retrieve Synchronizable Items
- ``querySynchronizable(forAccount:service:accessGroup:completion:)``
- ``querySynchronizable(forAccount:service:accessGroup:)``

- ``querySynchronizableKey(forAccount:service:accessGroup:completion:)``
- ``querySynchronizableKey(forAccount:service:accessGroup:)-2txdb``
- ``querySynchronizableKey(forAccount:service:accessGroup:)-7ax6a``

### Save and Update Synchronizable Items
- ``saveSynchronizable(_:forAccount:service:accessGroup:accessibility:label:)``

- ``saveSynchronizableKey(_:forAccount:service:accessGroup:accessibility:label:)-9nzj6``
- ``saveSynchronizableKey(_:forAccount:service:accessGroup:accessibility:label:)-2jzel``

- ``upsertSynchronizable(_:forAccount:service:accessGroup:accessibility:label:)``

- ``updateSynchronizable(newPassword:forAccount:service:accessGroup:)``

### Delete Synchronizable Items
- ``deleteSynchronizable(forAccount:service:accessGroup:)``

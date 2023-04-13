# ``DVESecurity/Keychain/InternetPassword``

## Overview

Internet password keychain items are usually used to save passwords for network services. They are stored as UTF-8 encoded strings in the keychain.

Internet passwords are uniquely identified by the access group they blong to and a combination of their `account`, `security domain`, `server`, `protocol`, `authentication type`, `port` and `path` attributes. All attributes except the `account` attribute are optional.

```swift
try Keychain.InternetPassword.save("MySecret", forAccount: "MyAccount")

let secret = try Keychain.InternetPassword.queryOne(forAccount: "MyAccount")
```

## Topics

### Retrieve Passwords
- ``queryOne(forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:authentication:completion:)``
- ``queryOne(forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:authentication:)-5c6gh``
- ``queryOne(forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:authentication:)-8tu60``

- ``queryItems(forAccount:securityDomain:server:protocol:authenticationType:port:path:accessGroup:authentication:completion:)``
- ``queryItems(forAccount:securityDomain:server:protocol:authenticationType:port:path:accessGroup:authentication:)-3aw10``
- ``queryItems(forAccount:securityDomain:server:protocol:authenticationType:port:path:accessGroup:authentication:)-8bk6n``

### Save and Update Passwords
- ``save(_:forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:accessControl:label:authenticationContext:)``

- ``upsert(_:forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:accessControl:label:authentication:)``

- ``updateItems(newPassword:forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:accessControl:authentication:)``

### Delete Passwords
- ``deleteItems(forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:)``

### Retrieve Synchronizable Passwords
- ``queryOneSynchronizable(forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:completion:)``
- ``queryOneSynchronizable(forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:)``

### Save and Update Synchronizable Passwords
- ``saveSynchronizable(_:forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:accessibility:label:)``

- ``upsertSynchronizable(_:forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:accessibility:label:)``

- ``updateSynchronizableItems(newPassword:forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:)``

### Delete Synchronizable Passwords
- ``deleteSynchronizableItems(forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:)``

### Internet Password Attributes
- ``AuthenticationType``
- ``NetworkProtocol``

# ``DVESecurity/Keychain/InternetPassword``

## Overview

Internet password keychain items are usually used to save passwords for network services. They are stored as UTF-8 encoded strings in the keychain.

Internet passwords are uniquely identified by the access group they blong to and a combination of their `account`, `security domain`, `server`, `protocol`, `authentication type`, `port` and `path` attributes. All attributes except the `account` attribute are optional.

- Note: Due to an issue / limitation in iOS 12, the synchronous query methods are only available for iOS 13 and later.
With iOS 12 a synchronous query on the main thread leads to a deadlock when the keychain services try to display a UI due to an access control restriction.

## Topics

### Retrieve Passwords
- ``queryOne(forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:authentication:completion:)``
- ``queryOne(forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:authentication:)``
- ``queryOnePublisher(forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:authentication:)``

- ``queryItems(account:securityDomain:server:protocol:authenticationType:port:path:accessGroup:authentication:completion:)``
- ``queryItems(account:securityDomain:server:protocol:authenticationType:port:path:accessGroup:authentication:)``

### Save and Update Passwords
- ``save(_:forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:accessControl:label:authenticationContext:)``
- ``savePublisher(for:account:accessGroup:securityDomain:server:protocol:authenticationType:port:path:accessControl:authenticationContext:)``

- ``upsert(_:forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:accessControl:label:authentication:)``

- ``updateItems(newPassword:forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:accessControl:authentication:)``

### Delete Passwords
- ``deleteItems(forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:accessControl:)``

### Retrieve Synchronizable Passwords
- ``queryOneSynchronizable(forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:completion:)``
- ``queryOneSynchronizable(forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:)``
- ``queryOneSynchronizablePublisher(forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:)``

### Save and Update Synchronizable Passwords
- ``saveSynchronizable(_:forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:accessibility:label:)``
- ``saveSynchronizablePublisher(for:account:accessGroup:securityDomain:server:protocol:authenticationType:port:path:accessibility:)``

- ``upsertSynchronizable(_:forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:accessibility:label:)``

- ``updateSynchronizableItems(newPassword:forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:)``

### Delete Synchronizable Passwords
- ``deleteSynchronizableItems(forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:)``

### Internet Password Attributes
- ``AuthenticationType``
- ``NetworkProtocol``

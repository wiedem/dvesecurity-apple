# ``DVESecurity/Keychain/InternetPassword``

## Overview

Internet password keychain items are usually used to save passwords for network services. They are stored as UTF-8 encoded strings in the keychain.
Other character encodings are currently not supported.

- Important: Internet passwords are uniquely identified by the access group they blong to and a combination of their `account`, `security domain`, `server`, `protocol`, `authentication type`, `port` and `path` attributes. All attributes except the `account` attribute are optional.

## Saving Passwords
For passwords that do not yet exist in the keychain, the ``InternetPassword/save(_:forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:accessControl:label:authenticationContext:)`` method can be used.

```swift
try Keychain.InternetPassword.save("MySecret", forAccount: "MyAccount")
```

For an account that allows access over multiple network protocols, multiple passwords may be stored for the same account.
```swift
try Keychain.InternetPassword.save("MySecret1", forAccount: "MyAccount", protocol: .http)
try Keychain.InternetPassword.save("MySecret2", forAccount: "MyAccount", protocol: .ssh)
```

If a password for the specified parameters already exists in the keychain, the function fails with a ``KeychainError/itemSavingFailed(status:)`` error and a `errSecDuplicateItem` status code.

To save a new password if none exists yet or to update an existing one, the method ``InternetPassword/upsert(_:forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:accessControl:label:authentication:)`` can be used.

```swift
try Keychain.InternetPassword.upsert("MySecret", forAccount: "MyAccount")
```

## Updating Passwords
If it does not matter if a password already exists, the ``InternetPassword/upsert(_:forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:accessControl:label:authentication:)`` method should be used.

In case a password should only be updated if it already exists in the keychain, there is the ``updateItems(newPassword:forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:accessControl:authentication:)`` method.

Trying to use the `updateItems` method for passwords that don't exist will throw a ``KeychainError/itemUpdateFailed(status:)`` with a `errSecItemNotFound` status code.

- Important: This method may update one or more items, depending on the parameters specified.

If the account 'MyAccount' in the following example has several passwords, e.g. for different network protocols, all passwords for this account will be updated.
```swift
try Keychain.InternetPassword.upsert(newPassword: "CHANGED", forAccount: "MyAccount")
```

## Querying Passwords
To query a single password item from the keychain the ``InternetPassword/queryOne(forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:authentication:)-5c6gh`` or one of the asynchronous variants can be used. 

```swift
let secret = try Keychain.InternetPassword.queryOne(forAccount: "MyAccount")
```

For unique retrieval, always use the same parameters that were used for saving.
If, for example, a network protocol was specified when saving, this should also be specified in the query.
```swift
let secret = try Keychain.InternetPassword.queryOne(forAccount: "MyAccount", protocol: .http)
```

If an attempt is made to retrieve an entry with parameters using the ``InternetPassword/queryOne(forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:authentication:)-5c6gh`` that does not return a unique result, a ``KeychainError/ambiguousQueryResult`` error is thrown.

To query all keychain items for an account use the ``InternetPassword/queryItems(forAccount:securityDomain:server:protocol:authenticationType:port:path:accessGroup:authentication:)-3aw10`` methods or the asynchronous variants.

```swift
let items = try Keychain.InternetPassword.queryItems(forAccount: "MyAccount")
items.forEach {
  print("password is '\($0.password)' for protocol '\($0.protocol)'")
}
```

- Important: The ``InternetPassword/queryItems(forAccount:securityDomain:server:protocol:authenticationType:port:path:accessGroup:authentication:)-3aw10`` method returns both synchronizable and non-synchronizable items. The ``InternetPassword/Item/synchronizable`` property indicates the type of the password item.

## Deleting Passwords
Password items can be deleted with the ``InternetPassword/deleteItems(forAccount:accessGroup:securityDomain:server:protocol:authenticationType:port:path:)`` method.

This method will delete one or more password items depending on the parameters specified.
```swift
let result = try Keychain.InternetPassword.deleteItems(forAccount: "MyAccount")
```

This method does not throw an error if no elements with the specified parameters could be found, instead the method returns `false` if no elements were deleted.

If there are multiple passwords for the specified account, all associated passwords will be deleted.
To further limit the operation, additional parameters can be specified, which were also used when saving the passwords.

## Access Groups
Internet passwords can be saved and queried for different access groups to share them with other apps or app extensions.
The list of available access groups for the app can be retrieved with the ``Keychain/accessGroups`` property.

By default, passwords are stored in the default access group defined by the ``Keychain/defaultAccessGroup`` property.

```swift
try Keychain.InternetPassword.save("MySecret", forAccount: "MyAccount", accessGroup: "com.example-app.app2")

let secret = try Keychain.InternetPassword.queryOne(forAccount: "MyAccount", accessGroup: "com.example-app.app2")
```

Trying to save a password for an access group that doesn't exist will throw a ``KeychainError/itemSavingFailed(status:)`` error with the status code `errSecMissingEntitlement`.

## Synchronizable Passwords
Internet passwords can be stored in the keychain as items that can be synchronized with iCloud.

For operations specific to synchronizable passwords, there are appropriately named methods that are otherwise identical in function to those of non-synchronizable passwords.

```swift
try Keychain.InternetPassword.saveSynchronizable("MySecret", forAccount: "MyAccount")
try Keychain.InternetPassword.upsertSynchronizable("MySecret", forAccount: "MyAccount")
try Keychain.InternetPassword.updateSynchronizableItems(newPassword: "CHANGED", forAccount: "MyAccount")
let result = try Keychain.InternetPassword.deleteSynchronizableItems(forAccount: "MyAccount")
```

- Note: Synchronized and non-synchronized Internet passwords are separated from each other. For example, an account may have a synchronized and a non-synchronized password at the same time.

- Important: The ``InternetPassword/queryItems(forAccount:securityDomain:server:protocol:authenticationType:port:path:accessGroup:authentication:)-3aw10`` method returns both synchronizable and non-synchronizable items. The ``InternetPassword/Item/synchronizable`` property indicates the type of the password item.

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

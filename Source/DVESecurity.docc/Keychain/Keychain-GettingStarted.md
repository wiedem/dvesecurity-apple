# Getting Started with Keychains

A keychain should be used whenever you want to store credentials or cryptographic keys locally in a secure manner.
For this purpose, both iOS and macOS offer a system keychain.

DVESecurity makes it easy to use the keychain APIs and prevents incorrect use wherever possible or clearly points out potential problems.

## Keychain Types
On iOS, only the modern `Data Protection Keychain` of the system is available. All functionalities for this keychain type can be found in the ``Keychain`` container.

On macOS, in addition to the modern `Data Protection Keychain`, there are legacy file-based keychains.

macOS offers both a modern and a legacy keychain type as system keychains. In addition, macOS apps can also create and use their own legacy keychain files, which are independent of the system keychain. The functionality for legacy keychain types is contained in the ``Keychain/Legacy`` type.

- Important: Using the `Data Protection Keychain` on macOS requires that the application has an `Application Identifier`. While all iOS apps usually have the required entitlement set, this usually has to be explicitly done for macOS apps.

The two keychain types differ in terms of available features and access control. In particular, `SecKey` instances created for one keychain type cannot be used in the other type without issues. Another example is synchronized keychain entries (via iCloud), which are only supported by the `Data Protection Keychain`.

- Note: The use of legacy file-based keychains is deprecated as of macOS 12.0. It is generally recommended to use the modern `Data Protection Keychain`.

## Keychain Entry Types
Keychains support a set of predefined entry types based on their application purpose. The individual types are partly encapsulated in their own containers for easier use.

### Internet Passwords
Internet password items are usually used for network credentials. The functions and types for this are encapsulated in the ``Keychain/InternetPassword`` container.

### Generic Passwords
Generic passwords are entries that are not intended to be assigned to any specific purpose. The value of such entries is usually a data object that must be converted to the appropriate type by the app.

This allows this type to be used when the credential is not assignable to the other available keychain entry types.

Generic password functionality is encapsulated in the ``Keychain/GenericPassword``container.

### Cryptographic Keys
The ``Keychain`` container contains generic methods for the different cryptographic key types.
The methods to be used are determined by the protocols implemented by the key types.

AES key types should implement the ``SecureData`` protocol while RSA keys implement the ``RSAPublicKey`` and ``RSAPrivateKey`` and Elliptic Curve Crypto keys implement the ``ECCPublicKey``and ``ECCPrivateKey`` methods.

For further requirements on the protocols to be implemented, see the corresponding methods.

The ``Crypto`` container contains predefined key types that meet these protocols and can thus be used with the keychain.

The following example shows the use of the keychain with the key types from the ``Crypto`` container:
```swift
// Create a random AES key and save it in the keychain.
// The tag and application label values are used to identify the entry and to query them later.
let aesKey = try Crypto.AES.Key(
    keySize: .bits256,
    password: "Hello Test!",
    withSalt: "Salt",
    pseudoRandomAlgorithm: .hmacAlgSHA256,
    rounds: 10000
)
try Keychain.saveKey(key, withTag: "AESKeyTag", applicationLabel: "SearchLabel")

// Create random RSA / ECC private keys and save them in the keychain.
// The items are identified by a tag value can also be queried by the SHA1 of their public keys.
let rsaKey = try Crypto.RSA.PrivateKey(bitCount: 2048)
try Keychain.saveKey(rsaKey, withTag: "RSAKeyTag")

let eccKey = Crypto.ECC.PrivateKey(curve: .p256)
try Keychain.saveKey(eccKey, withTag: "ECCKeyTag")
```

Note that with asymmetric keys, currently only private keys can be stored in the keychain.

### Secure Enclave Keys
Modern iOS and macOS devices support the [Secure Enclave](https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web) which can be used for secure cryptographic operations.

Since private keys generated in the Secure Enclave never leave its system, they cannot be stored directly in the keychain. Instead, a reference to the Secure Enclave is stored in the keychain, which allows a Secure Enclave key to be used for cryptographic operations.

Keys need to implement the ``ECCSecureEnclaveKey`` protocol in order to be used with the keychain. The ``Crypto/ECC/SecureEnclaveKey`` implements this protocol:
```swift
let secureEnclaveKey = try Crypto.ECC.SecureEnclaveKey()
try Keychain.saveKey(key, withTag: "SecureEnclaveKeyTag")
```

Note that Secure Enclave key type defined by the [CryptoKit](https://developer.apple.com/documentation/cryptokit) framework cannot be stored using this keychain type. Instead they have to be saved as a Generic Password item (see ``Keychain/GenericPassword``).

### Synchronized Entries
All keychain types can be stored as sychronized entries in the Data Protection Keychain, contrary to what can be found in Apple's keychain documentation. The only exception is the Secure Enclave keys.

If the user has enabled iCloud synchronization of the keychain on the system, these entries will be automatically synchronized with other devices of the user.

For each keychain item type in the keychain there are corresponding methods that contain the term `synchronizable` in their name. Synchronized entries have a few access control limitations, as they cannot logically be bound to a specific device.

The following example shows how to store a keychain entry of the Internet Password type as a synchronized entry:
```swift
try Keychain.InternetPassword.saveSynchronizable(password, forAccount: account)
```

- Note: The legacy file-based keychains of macOS do not support synchronization of entries via iCloud.

### CryptoKit Compatibility
All key types from the [CryptoKit](https://developer.apple.com/documentation/cryptokit) framework are directly supported by the methods of the ``Keychain`` container.

If a key type is directly supported by the keychain, the corresponding keychain types can be used, as we can see in the following example for a ECC P256 private key:
```swift
let privateKey = P256.Signing.PrivateKey()
try Keychain.saveKey(privateKey, withTag: "CryptoKitKey")
```

If there is no equivalent in the keychain for the cryptographic key type, they can be stored as Generic Password:
```swift
let privateKey = Curve25519.KeyAgreement.PrivateKey()
try Keychain.GenericPassword.saveKey(privateKey, forAccount: account, service: service)
```

```swift
let privateKey = try SecureEnclave.P256.Signing.PrivateKey()
try Keychain.GenericPassword.saveKey(privateKey, forAccount: account, service: service)
```

## Sharing Keychain Items
Keychain items can be shared with app extensions and other apps via access groups.
See [Sharing Access to Keychain Items Among a Collection of Apps](https://developer.apple.com/documentation/security/keychain_services/keychain_items/sharing_access_to_keychain_items_among_a_collection_of_apps) for a detailed description on how to setup your apps and app extensions.

All query methods of the keychain item types in the ``Keychain`` container have an `accessGroup` parameter that can be used to specify the access group for the query.
By default, this parameter always uses the access group returned by ``Keychain/defaultAccessGroup``.

Retrieving keychain objects without specifying an access group could lead to an ambiguous query result. The `accessGroup` parameter ensures that the result is unique for all queries.

The access groups used by an app can be retrieved with the ``Keychain/accessGroups`` property.

- Note: macOS apps by default don't have an application identifier nor an access group. Make sure you add an application identifier to your app if you want to use keychain functions requiring an access group.

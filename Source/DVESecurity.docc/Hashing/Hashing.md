# ``DVESecurity/Hashing``

## Overview
All hashing types defined in the container conform to the ``HashFunction`` protocol.

In simple cases, hashes can be generated directly from types that satisfy the [DataProtocol](https://developer.apple.com/documentation/foundation/dataprotocol):
```swift
let data = "Hello World!".data(using: .utf8)!
let hash = Hashing.SHA256.hash(data)
```
```swift
let hash = Hashing.SHA256.hash([0x01, 0x02, 0x03, 0x04])
```

In more complex cases, hashes can also be generated incrementally:
```swift
let part1: [UInt8] = [0x01, 0x02, 0x03, 0x04]
let part2: [UInt8] = [0x01, 0x02, 0x03, 0x04]

let hashFunction = Hashing.SHA256()
hashFunction.update(part1)
hashFunction.update(part2)
let hash = hashFunction.finalize()
```

## Non-Cryptographic Hashing
For non-cryptographic functions, hashing methods such as MD5 are available in the ``Insecure`` container.

```swift
let bytes: [UInt8] = [0x01, 0x02, 0x03, 0x04]
let hash = Hashing.Insecure.MD5.hash(bytes)
```

- Important: Hashing functions in the ``Insecure`` container should not be used for cryptographic purposes.

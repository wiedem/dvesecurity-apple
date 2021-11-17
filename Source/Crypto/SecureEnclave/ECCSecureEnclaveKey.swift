// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

/// A type for Secure Enclave Elliptic Curve Cryptography (ECC) keys.
///
/// See [Storing Keys in the Secure Enclave](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_secure_enclave).
public protocol ECCSecureEnclaveKey: DefinesSecKeyClass {}

// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

/// A type for Elliptic Curve Cryptography (ECC) public keys.
public protocol ECCPublicKey: ECCKey, X963Convertible, DefinesSecKeyClass {}

// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import CommonCrypto
import Foundation

/// Errors that can occur during CommonCrypto operations.
public struct CommonCryptoError: Error {
    public let status: CCCryptorStatus
}

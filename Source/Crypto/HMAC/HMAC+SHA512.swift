// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import CommonCrypto
import Foundation

extension Hashing.SHA512: CCHmacAlgorithmMapping {
    public static var ccHmacAlgorithm: CCHmacAlgorithm {
        CCHmacAlgorithm(kCCHmacAlgSHA512)
    }
}

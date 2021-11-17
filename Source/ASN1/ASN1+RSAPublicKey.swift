// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
#if canImport(DVESecurity_ObjC)
import DVESecurity_ObjC
#endif

public extension ASN1.RSAPublicKey {
    convenience init(pkcs1Data: Data) throws {
        var error: NSError?
        self.init(__pkcs1Data: pkcs1Data, error: &error)
        guard error == nil else {
            throw error!
        }
    }

    convenience init<Bytes>(pkcs1Bytes: Bytes) throws where Bytes: ContiguousBytes {
        let pkcs1Data = pkcs1Bytes.withUnsafeBytes { Data($0) }
        try self.init(pkcs1Data: pkcs1Data)
    }
}

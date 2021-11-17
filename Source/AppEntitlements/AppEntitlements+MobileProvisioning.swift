// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

public extension AppEntitlements {
    class func getEmbeddedMobileProvisioningData() throws -> Data? {
        guard let fileURL = Bundle.main.url(forResource: "embedded", withExtension: "mobileprovision") else {
            return nil
        }

        return try Data(contentsOf: fileURL, options: .dataReadingMapped)
    }
}

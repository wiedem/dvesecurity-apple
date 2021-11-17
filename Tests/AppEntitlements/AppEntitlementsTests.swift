// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import XCTest

class AppEntitlementsTests: XCTestCase {
    func testAppEntitlements() throws {
        expect(AppEntitlements.applicationIdentifier.hasSuffix("com.diva-e.DVESecurityTestApp")) == true

        expect(AppEntitlements.keychainAccessGroups).to(containElementSatisfying({ group in
            return group.hasSuffix("com.diva-e.DVESecurityTestApp")
        }))
        expect(AppEntitlements.keychainAccessGroups).to(containElementSatisfying({ group in
            return group.hasSuffix("com.diva-e.DVESecurityTestApp2")
        }))

        expect(AppEntitlements.applicationGroups).to(beNil())
        expect(AppEntitlements.getTaskAllow) == true

        #if targetEnvironment(simulator)
        expect(AppEntitlements.developerTeamIdentifier).to(beNil())
        #else
        expect(AppEntitlements.developerTeamIdentifier).toNot(beNil())
        #endif
    }
}

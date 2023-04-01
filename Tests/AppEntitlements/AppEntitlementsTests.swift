// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import XCTest

final class AppEntitlementsTests: XCTestCase {
    func testAppEntitlements() throws {
        expect(AppEntitlements.applicationIdentifier.hasSuffix("\(Self.productDomain).DVESecurityTestApp")) == true

        expect(AppEntitlements.keychainAccessGroups).to(containElementSatisfying({ group in
            return group.hasSuffix("\(Self.productDomain).DVESecurityTestApp")
        }))
        expect(AppEntitlements.keychainAccessGroups).to(containElementSatisfying({ group in
            return group.hasSuffix("\(Self.productDomain).DVESecurityTestApp2")
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

private extension AppEntitlementsTests {
    private static let productDomain = Bundle.main.object(forInfoDictionaryKey: "ProductDomain")! as! String
}

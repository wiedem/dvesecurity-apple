// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import Security
import XCTest

class SecKeyClassTests: XCTestCase {
    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    func testInsertSecAttrIntoForSymmetricKeyClass() throws {
        let symmetricKeyClass: SecKeyClass = .symmetric
        var attributes = [String: Any]()
        symmetricKeyClass.insertIntoKeychainQuery(&attributes)

        expect(attributes).to(haveCount(1))
        expect(attributes[kSecAttrKeyClass as String] as? String) == symmetricKeyClass.secAttrString
    }

    func testInsertSecAttrIntoForUndefinedKeyClass() throws {
        let undefinedKeyClassNoType: SecKeyClass = .undefined(nil)
        var attributes = [String: Any]()
        undefinedKeyClassNoType.insertIntoKeychainQuery(&attributes)

        expect(attributes).to(beEmpty())

        for keyType in SecKeyType.allCases {
            var attributes = [String: Any]()
            let undefinedKeyClassWithType: SecKeyClass = .undefined(keyType)
            undefinedKeyClassWithType.insertIntoKeychainQuery(&attributes)

            expect(attributes).to(haveCount(1))
            expect(attributes[kSecAttrKeyType as String] as? String) == keyType.secAttrString
        }
    }

    func testInsertSecAttrIntoForPublicKeyClass() throws {
        for keyType in SecKeyType.allCases {
            var attributes = [String: Any]()
            let keyClass: SecKeyClass = .public(keyType)
            keyClass.insertIntoKeychainQuery(&attributes)

            expect(attributes).to(haveCount(2))
            expect(attributes[kSecAttrKeyClass as String] as? String) == keyClass.secAttrString
            expect(attributes[kSecAttrKeyType as String] as? String) == keyType.secAttrString
        }
    }

    func testInsertSecAttrIntoForPrivteKeyClass() throws {
        for keyType in SecKeyType.allCases {
            var attributes = [String: Any]()
            let keyClass: SecKeyClass = .private(keyType)
            keyClass.insertIntoKeychainQuery(&attributes)

            expect(attributes).to(haveCount(2))
            expect(attributes[kSecAttrKeyClass as String] as? String) == keyClass.secAttrString
            expect(attributes[kSecAttrKeyType as String] as? String) == keyType.secAttrString
        }
    }
}

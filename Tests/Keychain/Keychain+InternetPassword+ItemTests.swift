// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@testable import DVESecurity
import Nimble
import XCTest

final class Keychain_InternetPassword_ItemTests: XCTestCase {
    func testCreationFromSecAttributes() throws {
        let passwordData = Data()
        let modificationDate = Date()
        let creationDate = Date()

        let attributes = [
            kSecValueData: passwordData,
            kSecAttrAccount: "account",
            kSecAttrSynchronizable: false,
            kSecAttrSecurityDomain: "domain",
            kSecAttrServer: "server",
            kSecAttrProtocol: kSecAttrProtocolHTTP,
            kSecAttrAuthenticationType: kSecAttrAuthenticationTypeHTTPBasic,
            kSecAttrPort: 80,
            kSecAttrPath: "path",
            kSecAttrModificationDate: modificationDate,
            kSecAttrCreationDate: creationDate,
            kSecAttrLabel: "label",
            kSecAttrDescription: "description",
            kSecAttrComment: "comment",
            kSecAttrCreator: 0,
        ] as [String: Any]

        let item = Keychain.InternetPassword.Item(attributes: attributes)

        expect(item.passwordData) == passwordData
        expect(item.account) == "account"
        expect(item.synchronizable) == false
        expect(item.securityDomain) == "domain"
        expect(item.server) == "server"
        expect(item.protocol) == .HTTP
        expect(item.authenticationType) == .HTTPBasic
        expect(item.port) == 80
        expect(item.path) == "path"
        expect(item.modificationDate) == modificationDate
        expect(item.creationDate) == creationDate
        expect(item.label) == "label"
        expect(item.description) == "description"
        expect(item.comment) == "comment"
        expect(item.creator) == 0
    }

    func testCreationFromMinSecAttributes() throws {
        let passwordData = Data()
        let modificationDate = Date()
        let creationDate = Date()

        let attributes = [
            kSecValueData: passwordData,
            kSecAttrAccount: "account",
            kSecAttrModificationDate: modificationDate,
            kSecAttrCreationDate: creationDate,
        ] as [String: Any]

        let item = Keychain.InternetPassword.Item(attributes: attributes)

        expect(item.passwordData) == passwordData
        expect(item.account) == "account"
        expect(item.synchronizable) == false
        expect(item.securityDomain) == ""
        expect(item.server) == ""
        expect(item.protocol).to(beNil())
        expect(item.authenticationType).to(beNil())
        expect(item.port) == 0
        expect(item.path) == ""
        expect(item.modificationDate) == modificationDate
        expect(item.creationDate) == creationDate
        expect(item.label).to(beNil())
        expect(item.description).to(beNil())
        expect(item.comment).to(beNil())
        expect(item.creator).to(beNil())
    }
}

// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import Security

extension Keychain.InternetPassword {
    static let itemClass: Keychain.ItemClass = .internetPassword
}

extension Keychain.InternetPassword.Item: KeychainAttributesConvertible {
    init(attributes: [String: Any]) {
        passwordData = attributes[kSecValueData as String] as! Data

        // Process the primary key attributes.
        // The Data Protection Keychain (macOS + iOS) never returns nil for the primary keys.
        // The file based keychains (macOS only) however does return nil values for those attributes.
        account = attributes[kSecAttrAccount as String] as! String
        synchronizable = (attributes[kSecAttrSynchronizable as String] as? NSNumber)?.boolValue == true

        securityDomain = attributes[kSecAttrSecurityDomain as String] as? String ?? ""
        server = attributes[kSecAttrServer as String] as? String ?? ""

        if let value = attributes[kSecAttrProtocol as String] as? String,
           let `protocol` = Keychain.InternetPassword.NetworkProtocol(secAttrString: value)
        {
            self.protocol = `protocol`
        } else {
            self.protocol = nil
        }

        if let value = attributes[kSecAttrAuthenticationType as String] as? String,
           let authenticationType = Keychain.InternetPassword.AuthenticationType(secAttrString: value)
        {
            self.authenticationType = authenticationType
        } else {
            authenticationType = nil
        }

        port = (attributes[kSecAttrPort as String] as? NSNumber)?.uint16Value ?? 0
        path = attributes[kSecAttrPath as String] as? String ?? ""

        // Date fields.
        modificationDate = attributes[kSecAttrModificationDate as String] as! Date
        creationDate = attributes[kSecAttrCreationDate as String] as! Date

        // Optional fields.
        label = attributes[kSecAttrLabel as String] as? String
        description = attributes[kSecAttrDescription as String] as? String
        comment = attributes[kSecAttrComment as String] as? String
        creator = (attributes[kSecAttrCreator as String] as? NSNumber)?.uint32Value
    }
}

extension Keychain.InternetPassword.NetworkProtocol {
    var secAttrString: String {
        switch self {
        case .FTP: return kSecAttrProtocolFTP as String
        case .FTPAccount: return kSecAttrProtocolFTPAccount as String
        case .HTTP: return kSecAttrProtocolHTTP as String
        case .IRC: return kSecAttrProtocolIRC as String
        case .NNTP: return kSecAttrProtocolNNTP as String
        case .POP3: return kSecAttrProtocolPOP3 as String
        case .SMTP: return kSecAttrProtocolSMTP as String
        case .SOCKS: return kSecAttrProtocolSOCKS as String
        case .IMAP: return kSecAttrProtocolIMAP as String
        case .LDAP: return kSecAttrProtocolLDAP as String
        case .AppleTalk: return kSecAttrProtocolAppleTalk as String
        case .AFP: return kSecAttrProtocolAFP as String
        case .Telnet: return kSecAttrProtocolTelnet as String
        case .SSH: return kSecAttrProtocolSSH as String
        case .FTPS: return kSecAttrProtocolFTPS as String
        case .HTTPS: return kSecAttrProtocolHTTPS as String
        case .HTTPProxy: return kSecAttrProtocolHTTPProxy as String
        case .HTTPSProxy: return kSecAttrProtocolHTTPSProxy as String
        case .FTPProxy: return kSecAttrProtocolFTPProxy as String
        case .SMB: return kSecAttrProtocolSMB as String
        case .RTSP: return kSecAttrProtocolRTSP as String
        case .RTSPProxy: return kSecAttrProtocolRTSPProxy as String
        case .DAAP: return kSecAttrProtocolDAAP as String
        case .EPPC: return kSecAttrProtocolEPPC as String
        case .IPP: return kSecAttrProtocolIPP as String
        case .NNTPS: return kSecAttrProtocolNNTPS as String
        case .LDAPS: return kSecAttrProtocolLDAPS as String
        case .TelnetS: return kSecAttrProtocolTelnetS as String
        case .IMAPSS: return kSecAttrProtocolIMAPS as String
        case .IRCS: return kSecAttrProtocolIRCS as String
        case .POP3S: return kSecAttrProtocolPOP3S as String
        }
    }

    // swiftlint:disable:next cyclomatic_complexity
    init?(secAttrString: String) {
        switch secAttrString as CFString {
        case kSecAttrProtocolFTP: self = .FTP
        case kSecAttrProtocolFTPAccount: self = .FTPAccount
        case kSecAttrProtocolHTTP: self = .HTTP
        case kSecAttrProtocolIRC: self = .IRC
        case kSecAttrProtocolNNTP: self = .NNTP
        case kSecAttrProtocolPOP3: self = .POP3
        case kSecAttrProtocolSMTP: self = .SMTP
        case kSecAttrProtocolSOCKS: self = .SOCKS
        case kSecAttrProtocolIMAP: self = .IMAP
        case kSecAttrProtocolLDAP: self = .LDAP
        case kSecAttrProtocolAppleTalk: self = .AppleTalk
        case kSecAttrProtocolAFP: self = .AFP
        case kSecAttrProtocolTelnet: self = .Telnet
        case kSecAttrProtocolSSH: self = .SSH
        case kSecAttrProtocolFTPS: self = .FTPS
        case kSecAttrProtocolHTTPS: self = .HTTPS
        case kSecAttrProtocolHTTPProxy: self = .HTTPProxy
        case kSecAttrProtocolHTTPSProxy: self = .HTTPSProxy
        case kSecAttrProtocolFTPProxy: self = .FTPProxy
        case kSecAttrProtocolSMB: self = .SMB
        case kSecAttrProtocolRTSP: self = .RTSP
        case kSecAttrProtocolRTSPProxy: self = .RTSPProxy
        case kSecAttrProtocolDAAP: self = .DAAP
        case kSecAttrProtocolEPPC: self = .EPPC
        case kSecAttrProtocolIPP: self = .IPP
        case kSecAttrProtocolNNTPS: self = .NNTPS
        case kSecAttrProtocolLDAPS: self = .LDAPS
        case kSecAttrProtocolTelnetS: self = .TelnetS
        case kSecAttrProtocolIMAPS: self = .IMAPSS
        case kSecAttrProtocolIRCS: self = .IRCS
        case kSecAttrProtocolPOP3S: self = .POP3S
        default:
            return nil
        }
    }
}

extension Keychain.InternetPassword.AuthenticationType {
    var secAttrString: String {
        switch self {
        case .NTLM: return kSecAttrAuthenticationTypeNTLM as String
        case .MSN: return kSecAttrAuthenticationTypeMSN as String
        case .DPA: return kSecAttrAuthenticationTypeDPA as String
        case .RPA: return kSecAttrAuthenticationTypeRPA as String
        case .HTTPBasic: return kSecAttrAuthenticationTypeHTTPBasic as String
        case .HTTPDigest: return kSecAttrAuthenticationTypeHTTPDigest as String
        case .HTMLForm: return kSecAttrAuthenticationTypeHTMLForm as String
        case .Default: return kSecAttrAuthenticationTypeDefault as String
        }
    }

    init?(secAttrString: String) {
        switch secAttrString as CFString {
        case kSecAttrAuthenticationTypeNTLM: self = .NTLM
        case kSecAttrAuthenticationTypeMSN: self = .MSN
        case kSecAttrAuthenticationTypeDPA: self = .DPA
        case kSecAttrAuthenticationTypeRPA: self = .RPA
        case kSecAttrAuthenticationTypeHTTPBasic: self = .HTTPBasic
        case kSecAttrAuthenticationTypeHTTPDigest: self = .HTTPDigest
        case kSecAttrAuthenticationTypeHTMLForm: self = .HTMLForm
        case kSecAttrAuthenticationTypeDefault: self = .Default
        default:
            return nil
        }
    }
}

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
        case .ftp:
            return kSecAttrProtocolFTP as String
        case .ftpAccount:
            return kSecAttrProtocolFTPAccount as String
        case .http:
            return kSecAttrProtocolHTTP as String
        case .irc:
            return kSecAttrProtocolIRC as String
        case .nntp:
            return kSecAttrProtocolNNTP as String
        case .pop3:
            return kSecAttrProtocolPOP3 as String
        case .smtp:
            return kSecAttrProtocolSMTP as String
        case .socks:
            return kSecAttrProtocolSOCKS as String
        case .imap:
            return kSecAttrProtocolIMAP as String
        case .ldap:
            return kSecAttrProtocolLDAP as String
        case .appleTalk:
            return kSecAttrProtocolAppleTalk as String
        case .afp:
            return kSecAttrProtocolAFP as String
        case .telnet:
            return kSecAttrProtocolTelnet as String
        case .ssh:
            return kSecAttrProtocolSSH as String
        case .ftps:
            return kSecAttrProtocolFTPS as String
        case .https:
            return kSecAttrProtocolHTTPS as String
        case .httpProxy:
            return kSecAttrProtocolHTTPProxy as String
        case .httpsProxy:
            return kSecAttrProtocolHTTPSProxy as String
        case .ftpProxy:
            return kSecAttrProtocolFTPProxy as String
        case .smb:
            return kSecAttrProtocolSMB as String
        case .rtsp:
            return kSecAttrProtocolRTSP as String
        case .rtspProxy:
            return kSecAttrProtocolRTSPProxy as String
        case .daap:
            return kSecAttrProtocolDAAP as String
        case .eppc:
            return kSecAttrProtocolEPPC as String
        case .ipp:
            return kSecAttrProtocolIPP as String
        case .nntps:
            return kSecAttrProtocolNNTPS as String
        case .ldaps:
            return kSecAttrProtocolLDAPS as String
        case .telnets:
            return kSecAttrProtocolTelnetS as String
        case .imapss:
            return kSecAttrProtocolIMAPS as String
        case .ircs:
            return kSecAttrProtocolIRCS as String
        case .pop3s:
            return kSecAttrProtocolPOP3S as String
        }
    }

    // swiftlint:disable:next cyclomatic_complexity
    init?(secAttrString: String) {
        switch secAttrString as CFString {
        case kSecAttrProtocolFTP:
            self = .ftp
        case kSecAttrProtocolFTPAccount:
            self = .ftpAccount
        case kSecAttrProtocolHTTP:
            self = .http
        case kSecAttrProtocolIRC:
            self = .irc
        case kSecAttrProtocolNNTP:
            self = .nntp
        case kSecAttrProtocolPOP3:
            self = .pop3
        case kSecAttrProtocolSMTP:
            self = .smtp
        case kSecAttrProtocolSOCKS:
            self = .socks
        case kSecAttrProtocolIMAP:
            self = .imap
        case kSecAttrProtocolLDAP:
            self = .ldap
        case kSecAttrProtocolAppleTalk:
            self = .appleTalk
        case kSecAttrProtocolAFP:
            self = .afp
        case kSecAttrProtocolTelnet:
            self = .telnet
        case kSecAttrProtocolSSH:
            self = .ssh
        case kSecAttrProtocolFTPS:
            self = .ftps
        case kSecAttrProtocolHTTPS:
            self = .https
        case kSecAttrProtocolHTTPProxy:
            self = .httpProxy
        case kSecAttrProtocolHTTPSProxy:
            self = .httpsProxy
        case kSecAttrProtocolFTPProxy:
            self = .ftpProxy
        case kSecAttrProtocolSMB:
            self = .smb
        case kSecAttrProtocolRTSP:
            self = .rtsp
        case kSecAttrProtocolRTSPProxy:
            self = .rtspProxy
        case kSecAttrProtocolDAAP:
            self = .daap
        case kSecAttrProtocolEPPC:
            self = .eppc
        case kSecAttrProtocolIPP:
            self = .ipp
        case kSecAttrProtocolNNTPS:
            self = .nntps
        case kSecAttrProtocolLDAPS:
            self = .ldaps
        case kSecAttrProtocolTelnetS:
            self = .telnets
        case kSecAttrProtocolIMAPS:
            self = .imapss
        case kSecAttrProtocolIRCS:
            self = .ircs
        case kSecAttrProtocolPOP3S:
            self = .pop3s
        default:
            return nil
        }
    }
}

extension Keychain.InternetPassword.AuthenticationType {
    var secAttrString: String {
        switch self {
        case .ntlm:
            return kSecAttrAuthenticationTypeNTLM as String
        case .msn:
            return kSecAttrAuthenticationTypeMSN as String
        case .dpa:
            return kSecAttrAuthenticationTypeDPA as String
        case .rpa:
            return kSecAttrAuthenticationTypeRPA as String
        case .httpBasic:
            return kSecAttrAuthenticationTypeHTTPBasic as String
        case .httpDigest:
            return kSecAttrAuthenticationTypeHTTPDigest as String
        case .htmlForm:
            return kSecAttrAuthenticationTypeHTMLForm as String
        case .default:
            return kSecAttrAuthenticationTypeDefault as String
        }
    }

    init?(secAttrString: String) {
        switch secAttrString as CFString {
        case kSecAttrAuthenticationTypeNTLM:
            self = .ntlm
        case kSecAttrAuthenticationTypeMSN:
            self = .msn
        case kSecAttrAuthenticationTypeDPA:
            self = .dpa
        case kSecAttrAuthenticationTypeRPA:
            self = .rpa
        case kSecAttrAuthenticationTypeHTTPBasic:
            self = .httpBasic
        case kSecAttrAuthenticationTypeHTTPDigest:
            self = .httpDigest
        case kSecAttrAuthenticationTypeHTMLForm:
            self = .htmlForm
        case kSecAttrAuthenticationTypeDefault:
            self = .default
        default:
            return nil
        }
    }
}

// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

public extension Keychain.InternetPassword {
    // swiftlint:disable identifier_name
    /// Network protocol attribute of an Internet Password keychain entry.
    enum NetworkProtocol {
        case ftp
        case ftpAccount
        case http
        case irc
        case nntp
        case pop3
        case smtp
        case socks
        case imap
        case ldap
        case appleTalk
        case afp
        case telnet
        case ssh
        case ftps
        case https
        case httpProxy
        case httpsProxy
        case ftpProxy
        case smb
        case rtsp
        case rtspProxy
        case daap
        case eppc
        case ipp
        case nntps
        case ldaps
        case telnets
        case imapss
        case ircs
        case pop3s
    }
    // swiftlint:enable identifier_name
}

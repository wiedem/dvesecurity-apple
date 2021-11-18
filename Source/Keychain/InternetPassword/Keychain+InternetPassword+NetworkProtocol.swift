// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

public extension Keychain.InternetPassword {
    // swiftlint:disable identifier_name
    /// Network protocol attribute of an Internet Password keychain entry.
    enum NetworkProtocol {
        case FTP
        case FTPAccount
        case HTTP
        case IRC
        case NNTP
        case POP3
        case SMTP
        case SOCKS
        case IMAP
        case LDAP
        case AppleTalk
        case AFP
        case Telnet
        case SSH
        case FTPS
        case HTTPS
        case HTTPProxy
        case HTTPSProxy
        case FTPProxy
        case SMB
        case RTSP
        case RTSPProxy
        case DAAP
        case EPPC
        case IPP
        case NNTPS
        case LDAPS
        case TelnetS
        case IMAPSS
        case IRCS
        case POP3S
    }
    // swiftlint:enable identifier_name
}

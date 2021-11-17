// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import LocalAuthentication

public extension Keychain {
    /// Keychain query authentication.
    struct QueryAuthentication {
        /// Authentication context to use for the query.
        ///
        /// The following rules apply to the `authenticationContext`:
        /// * If  `authenticationContext` is not specified and if the item requires authentication, a new context will be created, used once, and discarded.
        /// * If  `authenticationContext` is specified with a context that has been previously authenticated, the operation will succeed without asking user for authentication.
        /// * If  `authenticationContext` is specified with a context that has not been previously authenticated, the system attempts authentication on the context. If successful, the context may be reused in subsequent keychain operations.
        public var authenticationContext: LAContext?

        /// A value indicating whether the user may be prompted for authentication.
        public var userInterface: AuthenticationUI

        /// Default keychain query authentication with no authentication context and the permission to show a user prompt with no addicional description if necessary.
        public static let `default`: Self = .init()

        public init(authenticationContext: LAContext? = nil, userInterface: AuthenticationUI = .default) {
            self.authenticationContext = authenticationContext
            self.userInterface = userInterface
        }
    }

    /// A value indicating whether the user may be prompted for authentication.
    enum AuthenticationUI {
        /// A value that indicates user authentication is allowed.
        ///
        /// When performing user authentication, the system includes the specified string in the user prompt. The app is responsible for text localization.
        case allow(prompt: @autoclosure () -> String? = nil)
        /// A value that indicates user authentication is disallowed.
        ///
        /// If this value is specified and user authentication is required, the query function returns an error with the status code `errSecInteractionNotAllowed`.
        case disallow
        /// A value that indicates items requiring user authentication should be skipped.
        ///
        /// Silently skip any items that require user authentication.
        case skip

        /// A default authentication UI value for keychain operations.
        ///
        /// The value allows an authentication UI without a custom prompt description.
        public static let `default`: Self = .allow()
    }
}

// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
#if canImport(Combine)
import Combine
import LocalAuthentication

public extension LAContext {
    /// Returns a publisher that evaluates an access control object for the specified operation.
    ///
    /// This publisher asynchronously evaluates an access control. Evaluating an access control may involve prompting the user for various kinds of interaction or
    /// authentication. The actual behavior is dependent on the access control and device type. It can also be affected by installed configuration profiles.
    ///
    /// The localized string you present to the user should provide a clear reason for why you are requesting they authenticate themselves, and what action you will
    /// be taking based on that authentication. This string should be provided in the user’s current language and should be short and clear. It should not contain the
    /// app name, because that appears elsewhere in the authentication dialog. In iOS this appears in the dialog subtitle.
    ///
    /// You should not assume that a previous successful evaluation of an access control necessarily leads to a subsequent successful evaluation. Access control
    /// evaluation can fail for various reasons, including cancelation by the user or the system.
    ///
    /// - Parameters:
    ///   - accessControl: The access control to be evaluated.
    ///   - operation: The operation for the access control to be evaluated. For possible values, see `LAAccessControlOperation`.
    ///   - localizedReason: The app-provided reason for requesting authentication, which displays in the authentication dialog presented to the user.
    func evaluateAccessControlPublisher(
        for accessControl: Keychain.AccessControl,
        operation: LAAccessControlOperation,
        localizedReason: String
    ) -> AnyPublisher<Void, Error> {
        Future { promise in
            self.evaluateAccessControl(accessControl, operation: operation, localizedReason: localizedReason) { result in
                promise(result)
            }
        }
        .eraseToAnyPublisher()
    }
}

#endif

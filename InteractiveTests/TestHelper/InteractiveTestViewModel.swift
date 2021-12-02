// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

public protocol InteractiveTestViewModel: AnyObject {
    func startActivity()
    func stopActivity()

    func removeLastTestSteps(_ count: Int)
    func setTestTitle(_ title: String?)
    func addTestDescription(_ description: String)
    func addTestAction(_ description: String, removeOnCompletion: Bool, action: @escaping () -> Void)
    func addOutput(_ output: String)

    #if os(iOS)
    func enableRemoteNotifications(handler: @escaping (Bool, [AnyHashable: Any]) -> Void)
    #endif
}

public extension InteractiveTestViewModel {
    func addTestAction(_ description: String, action: @escaping () -> Void) {
        addTestAction(description, removeOnCompletion: true, action: action)
    }
}

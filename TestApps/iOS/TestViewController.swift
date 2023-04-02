// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import UIKit

final class ButtonActionTarget {
    private let action: () -> Void

    init(_ action: @escaping () -> Void) {
        self.action = action
    }

    @objc func runAction(_: UIButton?) {
        action()
    }
}

public final class TestViewController: UIViewController, InteractiveTestViewModel {
    @IBOutlet private var stackView: UIStackView!
    @IBOutlet private var activityIndicatorView: UIActivityIndicatorView!
    @IBOutlet private var testStepsStackView: UIStackView!
    @IBOutlet private var descriptionLabel: UILabel!
    @IBOutlet private var outputStackView: UIStackView!
    @IBOutlet private var outputLabel: UILabel!
    @IBOutlet private var registerForRemoteNotificationsButton: UIButton!

    @IBOutlet private var scrollView: UIScrollView!
    @objc public var contentScrollView: UIScrollView? { scrollView }

    private let userNotificationCenter = UNUserNotificationCenter.current()

    private var deviceToken: Data?
    private var notificationOptions: UNAuthorizationOptions = [.badge, .sound, .alert]
    private var remoteNotificationHandler: ((Bool, [AnyHashable: Any]) -> Void)?

    public func startActivity() {
        activityIndicatorView.startAnimating()
    }

    public func stopActivity() {
        activityIndicatorView.stopAnimating()
    }

    public func enableRemoteNotifications(handler: @escaping (Bool, [AnyHashable: Any]) -> Void) {
        remoteNotificationHandler = handler
        userNotificationCenter.delegate = self
        registerForRemoteNotificationsButton.isHidden = false
    }

    public func removeLastTestSteps(_ count: Int) {
        let viewsToRemove = testStepsStackView.arrangedSubviews.suffix(count)
        viewsToRemove.forEach { $0.removeFromSuperview() }
    }

    public func setTestTitle(_ title: String?) {
        descriptionLabel.text = title
        descriptionLabel.isHidden = title == nil
    }

    public func addTestDescription(_ description: String) {
        let label = UILabel()
        label.translatesAutoresizingMaskIntoConstraints = false
        label.textColor = .white
        label.numberOfLines = 0
        label.text = description

        testStepsStackView.addArrangedSubview(label)
    }

    public func addTestAction(_ description: String, removeOnCompletion: Bool = true, action: @escaping () -> Void) {
        var buttonActionTarget: ButtonActionTarget!
        var button: UIButton!
        buttonActionTarget = ButtonActionTarget {
            action()
            if removeOnCompletion, button.superview != nil {
                button.removeFromSuperview()
            }
            buttonActionTarget = nil
        }

        button = UIButton(type: .roundedRect)
        button.translatesAutoresizingMaskIntoConstraints = false
        button.backgroundColor = .white
        button.contentEdgeInsets = UIEdgeInsets(top: 5, left: 15, bottom: 5, right: 15)
        button.setTitle(description, for: .normal)
        button.addTarget(buttonActionTarget, action: #selector(ButtonActionTarget.runAction(_:)), for: .touchUpInside)
        button.widthAnchor.constraint(greaterThanOrEqualToConstant: 150).isActive = true

        testStepsStackView.addArrangedSubview(button)
    }

    public func addOutput(_ output: String) {
        outputLabel.isHidden = false

        let textView = UITextView()

        textView.font = .preferredFont(forTextStyle: .footnote)
        textView.translatesAutoresizingMaskIntoConstraints = false
        textView.textColor = .white
        textView.isEditable = false
        textView.isScrollEnabled = false
        textView.textContainerInset = .zero
        textView.text = output

        outputStackView.addArrangedSubview(textView)
    }

    @IBAction private func registerForRemoteNotificationsAction(_: UIButton) {
        userNotificationCenter.requestAuthorization(options: notificationOptions) { [weak self] granted, error in
            guard let self else { return }

            DispatchQueue.main.async {
                if let authorizationError = error {
                    self.addOutput("Failed to request authorization: \(authorizationError)")
                    return
                }

                guard granted else {
                    self.addOutput("Authorization for remote notifications was denied.")
                    return
                }

                self.addOutput("Authorization for remote notifications was granted.")
                UIApplication.shared.registerForRemoteNotifications()
            }
        }
    }
}

extension TestViewController: UNUserNotificationCenterDelegate {
    public func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        NSLog("Received remote notification.")

        remoteNotificationHandler?(false, response.notification.request.content.userInfo)

        completionHandler()
    }

    public func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        NSLog("Showing notification while app is in foreground.")

        remoteNotificationHandler?(false, notification.request.content.userInfo)

        if #available(iOS 14.0, *) {
            completionHandler([.banner, .list, .badge, .sound])
        } else {
            completionHandler([.alert, .badge, .sound])
        }
    }
}

extension TestViewController {
    func didReceiveDeviceToken(_ token: Data) {
        deviceToken = token

        let tokenString = token.map { String(format: "%02hhx", $0) }.joined()
        NSLog("Device token: \(tokenString)")
        addOutput(tokenString)
    }

    func didFailToRegisterForRemoteNotificationsWithError(_ error: Error) {
        addOutput("Failed to register for remote notifications: \(error)")
    }

    func didReceiveBackgroundNotification(userInfo: [AnyHashable: Any]) {
        addOutput("Received remote notification")
        remoteNotificationHandler?(true, userInfo)
    }
}

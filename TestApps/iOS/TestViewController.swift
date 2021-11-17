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
    @IBOutlet private var testStepsStackView: UIStackView!
    @IBOutlet private var activityIndicatorView: UIActivityIndicatorView!
    @IBOutlet private var descriptionLabel: UILabel!

    public func startActivity() {
        activityIndicatorView.startAnimating()
    }

    public func stopActivity() {
        activityIndicatorView.stopAnimating()
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
}

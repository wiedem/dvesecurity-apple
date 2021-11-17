// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Cocoa

final class ButtonActionTarget {
    private let action: () -> Void

    init(_ action: @escaping () -> Void) {
        self.action = action
    }

    @objc func runAction(_: NSButton?) {
        action()
    }
}

public final class TestViewController: NSViewController, InteractiveTestViewModel {
    @IBOutlet private var stackView: NSStackView!
    @IBOutlet private var testStepsStackView: NSStackView!
    @IBOutlet private var progressIndicator: NSProgressIndicator!
    @IBOutlet private var descriptionTextField: NSTextField!

    override public func viewDidLoad() {
        super.viewDidLoad()

        progressIndicator.startAnimation(nil)
    }

    override public var representedObject: Any? {
        didSet {
            // Update the view, if already loaded.
        }
    }

    public func startActivity() {
        progressIndicator.startAnimation(nil)
    }

    public func stopActivity() {
        progressIndicator.stopAnimation(nil)
    }

    public func removeLastTestSteps(_ count: Int) {
        guard count >= testStepsStackView.arrangedSubviews.count else {
            testStepsStackView.arrangedSubviews.forEach { $0.removeFromSuperview() }
            return
        }
        let viewsToRemove = testStepsStackView.arrangedSubviews.suffix(count)
        viewsToRemove.forEach { $0.removeFromSuperview() }
    }

    public func setTestTitle(_ title: String?) {
        descriptionTextField.stringValue = title ?? ""
        descriptionTextField.isHidden = title == nil
    }

    public func addTestDescription(_ description: String) {
        let label = NSTextField(labelWithString: description)
        label.translatesAutoresizingMaskIntoConstraints = false
        label.textColor = .white
        label.maximumNumberOfLines = 0

        testStepsStackView.addArrangedSubview(label)
    }

    public func addTestAction(_ description: String, removeOnCompletion: Bool, action: @escaping () -> Void) {
        var buttonActionTarget: ButtonActionTarget!
        var button: NSButton!
        buttonActionTarget = ButtonActionTarget {
            action()
            if removeOnCompletion, button.superview != nil {
                button.removeFromSuperview()
            }
            buttonActionTarget = nil
        }

        button = NSButton(title: description, target: buttonActionTarget, action: #selector(ButtonActionTarget.runAction(_:)))
        button.translatesAutoresizingMaskIntoConstraints = false

        testStepsStackView.addArrangedSubview(button)
    }
}

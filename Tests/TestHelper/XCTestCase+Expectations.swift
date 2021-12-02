// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import XCTest

extension XCTestCase {
    typealias AsyncResultCompletionHandler<Success> = (Result<Success, Error>) -> Void
    typealias AsyncCompletionHandler<Success> = (Success) -> Void

    enum TaskWaitError: Error {
        case waitFailed(XCTWaiter.Result)
    }

    func wait<Success>(
        description: String,
        timeout: TimeInterval = defaultUIInteractionTimeout,
        for task: (_ taskCompletion: @escaping AsyncResultCompletionHandler<Success>) -> Void
    ) throws -> Success {
        var taskExpectation: XCTestExpectation? = expectation(description: description)

        var result: Result<Success, Error>?
        let handler: AsyncResultCompletionHandler<Success> = {
            result = $0
            taskExpectation?.fulfill()
        }

        task(handler)

        let waiterResult = XCTWaiter.wait(for: [taskExpectation!], timeout: timeout)
        taskExpectation = nil

        guard case .completed = waiterResult else {
            XCTFail("Failed to wait for task of expectation '\(description)': \(waiterResult).")
            throw TaskWaitError.waitFailed(waiterResult)
        }
        return try result!.get()
    }

    func wait<Success>(
        description: String,
        timeout: TimeInterval = defaultUIInteractionTimeout,
        for task: (_ taskCompletion: @escaping AsyncCompletionHandler<Success>) -> Void
    ) throws -> Success {
        var taskExpectation: XCTestExpectation? = expectation(description: description)

        var result: Success?
        let handler: AsyncCompletionHandler<Success> = {
            result = $0
            taskExpectation?.fulfill()
        }

        task(handler)

        let waiterResult = XCTWaiter.wait(for: [taskExpectation!], timeout: timeout)
        taskExpectation = nil

        guard case .completed = waiterResult else {
            XCTFail("Failed to wait for task of expectation '\(description)': \(waiterResult).")
            throw TaskWaitError.waitFailed(waiterResult)
        }
        return result!
    }

    func wait(expectationDescription: String, timeout: TimeInterval, for task: (XCTestExpectation?) -> Void) -> XCTWaiter.Result {
        var taskExpectation: XCTestExpectation? = expectation(description: expectationDescription)

        // Perform the async task and wait for the expectation to fulfill.
        task(taskExpectation)

        let waiterResult = XCTWaiter.wait(for: [taskExpectation!], timeout: timeout)
        taskExpectation = nil
        switch waiterResult {
        case .timedOut:
            XCTFail("Task for expectation '\(expectationDescription)' timed out.")
        case .interrupted:
            XCTFail("Task for expectation '\(expectationDescription)' was interrupted.")
        default:
            break
        }
        return waiterResult
    }
}

extension XCTWaiter.Result {
    var isCompleted: Bool {
        guard case .completed = self else { return false }
        return true
    }
}

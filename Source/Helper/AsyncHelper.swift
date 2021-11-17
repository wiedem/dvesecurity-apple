// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

enum TaskWaitError: Error {
    case timeout
}

@usableFromInline typealias TaskCompletionHandler<R, E> = (Result<R, E>) -> Void where E: Error

@discardableResult
@usableFromInline func waitFor<R, E>(
    timeout: TimeInterval = 0,
    _ task: @escaping (@escaping TaskCompletionHandler<R, E>) -> Void
) throws -> R where E: Error {
    var value: R?
    var error: E?

    let group = DispatchGroup()
    group.enter()
    var timedOut = false

    task { result in
        defer { group.leave() }
        guard timedOut == false else { return }

        switch result {
        case let .success(resultValue):
            value = resultValue
        case let .failure(resultError):
            error = resultError
        }
    }

    if timeout > 0 {
        switch group.wait(timeout: .now() + timeout) {
        case .timedOut:
            timedOut = true
            throw TaskWaitError.timeout
        case .success:
            break
        }
    } else {
        group.wait()
    }

    guard error == nil else { throw error! }
    return value!
}

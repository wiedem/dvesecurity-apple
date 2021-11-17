// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

extension Result {
    func tryMap<NewSuccess>(_ transform: (Success) throws -> NewSuccess) -> Result<NewSuccess, Failure> where Failure == Error {
        switch self {
        case let .failure(error):
            return .failure(error)

        case let .success(result):
            do {
                let transformed = try transform(result)
                return .success(transformed)
            } catch {
                return .failure(error)
            }
        }
    }
}

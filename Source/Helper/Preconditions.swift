// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

func expectNoError<T>(_ message: @autoclosure () -> String = String(), file: StaticString = #file, line: UInt = #line, perform: () throws -> T) -> T {
    do {
        return try perform()
    } catch {
        var fatalErrorMessage = "Unexpected fatal error in file \(file):\(line)\n\(error)"

        let userMessage = message()
        if userMessage.isEmpty == false {
            fatalErrorMessage += "\n" + userMessage
        }

        fatalError(fatalErrorMessage)
    }
}

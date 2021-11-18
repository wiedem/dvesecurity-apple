# DVESecurity Framework for iOS and macOS

DVESecurity is an open source framework for iOS and macOS that makes security-related functions of the [Security Framework] and the [CommonCrypto Library] easily accessible to your Swift apps and packages.

In particular, this includes cryptographic functions and the use of a keychain to protect application data.

## Using DVESecurity
DVESecurity can be used as a Swift package via the [Swift Package Manager], via [Carthage] or manually as a framework or library.

### Using the Swift Package Manager
To use the framework as a Swift package, add the following dependency to your `Package.swift`:
```swift
.package(url: "https://oss.diva-e.com/libraries/dvesecurity-apple", .upToNextMajor(from: "1.0.0")),
```

If a Swift version of 5.5 or higher is used, a [DocC] documentation for the framework is available. Further details can be found in the [Documentation](#Documentation) section.

Note that the framework does not have a test target in the Swift package manifest. For more details on testing, see the [Testing](#testing) section.

### Using Carthage
To use the framework as a Carthage dependency, add the following line to your `Cartfile`:
```
git "https://oss.diva-e.com/libraries/dvesecurity-apple" ~> 1.0
```

For more details about the integration via Carthage see the notes on the [Carthage] project page.

### Manual Integration
An Xcode project file is part of the repository and can be used for manual inclusion in your own Xcode projects.

## Testing
The framework's Xcode project includes automated and manual tests to test the functionality of the APIs.
Most of the tests require a host application with an application identifier to run. The project includes host applications for iOS and macOS for this purpose.

In order for the host applications to work, a configuration file `Local.xcconfig` must be created in the `Configuration` directory of the project that sets the application identifier domain and the development team for signing the app. The domain is defined with the variable `PRODUCT_DOMAIN` and the development team with the variable `DEVELOPMENT_TEAM`.

A sample `Local.xcconfig` file could look like this:
```
PRODUCT_DOMAIN = com.my-company

// Simulator environments don't require a development team
DEVELOPMENT_TEAM[sdk=iphonesimulator*] =
DEVELOPMENT_TEAM[sdk=iphoneos*] = XXXXXXXXXX
DEVELOPMENT_TEAM[sdk=macos*] = XXXXXXXXXX
```

The team identifier for your development team can be found in your [Apple developer account](https://developer.apple.com/account/#!/membership/).

Note that tests that require execution on a device are skipped in a simulator environment.

### Interactive Tests
Some tests require user interaction and are therefore in a separate test target `DVESecurityInteractiveTests`.  In particular, most keychain tests require execution on a device rather than in a simulator environment.

### Keychain Tests
The keychain tests are designed to leave the systems' keychains in a clean condition.
For the tests with the legacy macOS file-based keychains, a separate temporary keychain file is created for this purpose.
However, for tests with the Data Protection Keychain that are run on actual devices (iOS + macOS), the system's default keychain is used.

If a test is terminated irregularly, it can happen that keychain entries from the tests remain. Although this should have no negative impact on other applications or the system, it is recommended not to run these tests on production devices.

## Documentation
The framework is designed to generate a detailed [DocC] documentation.
It contains the API documentation as well as articles on getting started and code samples.

When the framework is included as a Swift package in Xcode, the documentation can be generated via the `Product > Build Documentation` menu item or the corresponding `xcodebuild` command from the command line.

If the framework is included via Carthage or manually as a library, then the documentation must be generated manually.  

## Compatibility
DVESecurity is compatible with iOS 12.4, macOS 10.15 and requires at least Swift 5.4.
The framework also follows the [SemVer 2.0.0] rules.

[Security Framework]: https://developer.apple.com/documentation/security "Security Framework"
[CommonCrypto Library]: https://opensource.apple.com/source/CommonCrypto/ "CommonCrypto Library"
[Swift Package Manager]: https://swift.org/package-manager/ "Swift Package Manager"
[Carthage]: https://github.com/Carthage/Carthage "Carthage"
[DocC]: https://developer.apple.com/documentation/docc "DocC"
[Swift-DocC]: https://www.swift.org/blog/swift-docc/ "Swift-DocC is Now Open Source"
[SemVer 2.0.0]: https://semver.org/#semantic-versioning-200 "Semantic Versioning 2.0.0"

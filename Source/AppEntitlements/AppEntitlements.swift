// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

/// Errors that can occur when reading the app entitlements.
public enum AppEntitlementsError: Error {
    case noBundleExecutable
    case failedToLoadExecutableSymbol(String)
    case failedToLoadLibrary(String)
    case invalidMachHeader
    case invalidMachFatHeader
    case invalidArchitecture
    case fatBinary
    case invalidSegmentStructure
    case missingEntitlements
}

/// A singleton class used to get the app's entitlements.
///
/// - SeeAlso: [Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
public final class AppEntitlements {
    private let entitlements: [String: Any]

    /// The app's identifier as defined in the entitlements.
    ///
    /// - Note: Attempting to access this value in a macOS application that does not have an application identifier will result in a fatal error.
    /// iOS applications are always guaranteed to have an application identifier.
    public class var applicationIdentifier: String {
        let appIDKey1 = EntitlementKey.associatedApplicationIdentifier.rawValue
        let appIDKey2 = EntitlementKey.applicationIdentifier.rawValue
        guard let appID = (shared.entitlements[appIDKey1] ?? shared.entitlements[appIDKey2]) as? String else {
            fatalError("Application doesn't have an identifier, make sure the app has a valid provisioning profile.")
        }
        return appID
    }

    /// The app's keychain access groups entitlement.
    ///
    /// The identifiers for the keychain groups that the app may share items with.
    public class var keychainAccessGroups: [String] {
        guard let keychainAccessGroups = shared.entitlements[EntitlementKey.keychainAccessGroups.rawValue] as? [String] else {
            return []
        }
        return keychainAccessGroups
    }

    /// The  app's `get-task-allow` entitlement defines whether other apps are allowed to get the task port of the app.
    ///
    /// If the value of this entitlement is set to `true` the `task_for_pid` function will be allowed for the app's process which means other processes may control and manipulate the app's process.
    ///
    /// This property usually is `true` for debug and development builds and `false` for distribution builds.
    public class var getTaskAllow: Bool {
        guard let entitlementsValue = shared.entitlements[EntitlementKey.getTaskAllow.rawValue] as? NSNumber
        else {
            return false
        }
        return Bool(truncating: entitlementsValue)
    }

    /// The app's application groups entitlement.
    ///
    /// A list of identifiers specifying the groups your app belongs to.
    public class var applicationGroups: [String]? {
        return shared.entitlements[EntitlementKey.appleSecurityApplicationGroups.rawValue] as? [String]
    }

    /// The app's development team identifier entitlement.
    public class var developerTeamIdentifier: String? {
        return shared.entitlements[EntitlementKey.appleDeveloperTeamIdentifier.rawValue] as? String
    }

    /// Apple Push Services (APS) environment used by the app.
    public class var apsEnvironment: String? {
        return shared.entitlements[EntitlementKey.apsEnvironment.rawValue] as? String
    }

    private init(_ entitlements: [String: Any]) {
        self.entitlements = entitlements
    }
}

private extension AppEntitlements {
    /// See [SecEntitlements.h](https://opensource.apple.com/source/Security/Security-59306.140.5/sectask/SecEntitlements.h.auto.html) and [App Sandbox](https://developer.apple.com/documentation/security/app_sandbox)
    enum EntitlementKey: String {
        // swiftlint:disable duplicate_enum_cases
        #if os(iOS)
        /// Entitlement key for the application identifier.
        ///
        /// Typically the value of this entitlement is same as the `CFBundleIdentifier`, prefixed with the team-id.
        case applicationIdentifier = "application-identifier"
        /// Entitlement key defining the APS Environment.
        ///
        /// See [APS Environmen Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/aps-environment)
        case apsEnvironment = "aps-environment"
        #elseif os(macOS)
        /// Entitlement key for the application identifier.
        ///
        /// Typically the value of this entitlement is same as the `CFBundleIdentifier`, prefixed with the team-id.
        case applicationIdentifier = "com.apple.application-identifier"
        /// Entitlement key defining the APS Environment.
        ///
        /// See [APS Environmen Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_developer_aps-environment)
        case apsEnvironment = "com.apple.developer.aps-environment"
        #endif
        #if os(macOS) || targetEnvironment(simulator)
        /// Entitlement key for the `get task` access control.
        ///
        /// This entitlement defines if other tasks can get the app's task name port. This is needed so the app can be debugged.
        case getTaskAllow = "com.apple.security.get-task-allow"
        #elseif os(iOS)
        /// Entitlement key for the `get task` access control.
        ///
        /// This entitlement defines if other tasks can get the app's task name port. This is needed so the app can be debugged.
        case getTaskAllow = "get-task-allow"
        #endif
        // swiftlint:enable duplicate_enum_cases
        /// Entitlement key for the associated application identifier.
        ///
        /// Associated application identifiers are used for `Catalyst` (formerly known as `Marzipan`) apps distributed through the App Store.
        case associatedApplicationIdentifier = "com.apple.developer.associated-application-identifier"
        /// Entitlement key for the app's keychain access groups.
        ///
        /// The value of this key is an array of strings, each string is the name of an access group that the application has access to.
        case keychainAccessGroups = "keychain-access-groups"
        /// Entitlement key for the app's security groups.
        ///
        /// The value of this key is an array of strings, each string is the name of an access group that the application has access to.
        ///
        /// The first of `keychainAccessGroups`, `applicationIdentifier` or `appleSecurityApplicationGroups` to have a value becomes the default application group for keychain clients that don't specify an explicit one.
        case appleSecurityApplicationGroups = "com.apple.security.application-groups"
        /// Entitlement key for the team identifier of the app.
        case appleDeveloperTeamIdentifier = "com.apple.developer.team-identifier"
        #if os(macOS)
        /// Entitlement key indicating if the app is sandboxed.
        ///
        /// The value of this key is a Boolean that indicates whether the app may use access control technology to contain damage to the system and user data if an app is compromised.
        case applicationSandbox = "com.apple.security.app-sandbox"
        #endif
    }

    static let shared: AppEntitlements = createSharedInstance()

    class func createSharedInstance() -> AppEntitlements {
        do {
            guard let appEntitlements = try embeddedCodeSigningEntitlements(),
                  appEntitlements.isEmpty == false
            else {
                throw AppEntitlementsError.missingEntitlements
            }
            return AppEntitlements(appEntitlements)
        } catch AppEntitlementsError.fatBinary, CodeSignatureError.fatBinary {
            fatalError("Error getting entitlements in application binary. Unsupported fat binary with multiple architectures.")
        } catch AppEntitlementsError.invalidMachHeader, CodeSignatureError.invalidMachHeader {
            fatalError("Error getting entitlements in application binary. Unsupported or unknown binary.")
        } catch {
            fatalError("Error getting entitlements in application binary: \(error).")
        }
    }
}

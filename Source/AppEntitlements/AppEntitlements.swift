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

/// A singleton class providing access to the app's entitlements.
///
/// - See: [Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
public final class AppEntitlements {
    private let entitlements: [String: Any]

    public enum ICloudContainerEnvironment: String {
        case production = "Production"
        case development = "Development"
    }

    public enum ICloudServices: String {
        case cloudDocuments = "CloudDocuments"
        case cloudKit = "CloudKit"
        case cloudKitAnonymous = "CloudKit-Anonymous"
    }

    /// The app's identifier as defined in the entitlements.
    ///
    /// - Note: Attempting to access this value in a macOS application that does not have an application identifier will result in a fatal error.
    ///
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
        shared.entitlements[EntitlementKey.appleSecurityApplicationGroups.rawValue] as? [String]
    }

    /// The app's development team identifier entitlement.
    public class var developerTeamIdentifier: String? {
        shared.entitlements[EntitlementKey.appleDeveloperTeamIdentifier.rawValue] as? String
    }

    /// Apple Push Services (APS) environment used by the app.
    public class var apsEnvironment: String? {
        shared.entitlements[EntitlementKey.apsEnvironment.rawValue] as? String
    }

    #if os(iOS)
    /// The default data protection level entitlement of the app.
    ///
    /// The value of this entitlement defines the default protection level for newly created files.
    ///
    /// See [Data Protection Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_developer_default-data-protection).
    public class var defaultDataProtection: FileProtectionType? {
        guard let defaultDataProtectionValue = shared.entitlements[EntitlementKey.defaultDataProtection.rawValue] as? String else {
            return nil
        }
        return .init(rawValue: defaultDataProtectionValue)
    }
    #endif

    #if os(macOS)
    /// Indicates if the app has the [App Sandbox Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_app-sandbox) set.
    ///
    /// This value indicates whether the app may use access control technology to contain damage to the system and user data if an app is compromised.
    ///
    /// See [App Sandbox](https://developer.apple.com/documentation/security/app_sandbox).
    public class var isAppSandboxed: Bool {
        shared.entitlements[EntitlementKey.applicationSandbox.rawValue] as? Bool ?? false
    }
    #endif

    /// A list of associated domains for specific services, such as shared web credentials, universal links, and App Clips.
    public class var associatedDomains: [String] {
        shared.entitlements[EntitlementKey.associatedDomains.rawValue] as? [String] ?? []
    }

    /// A list of container identifiers for the iCloud development environment.
    public class var iCouldContainerIdentifiers: [String] {
        shared.entitlements[EntitlementKey.iCouldContainerIdentifiers.rawValue] as? [String] ?? []
    }

    /// The environment to use for the iCloud containers.
    public class var iCouldContainerEnvironment: ICloudContainerEnvironment? {
        guard let iCouldContainerEnvironmentValue = shared.entitlements[EntitlementKey.iCouldContainerEnvironment.rawValue] as? String else {
            return nil
        }
        return .init(rawValue: iCouldContainerEnvironmentValue)
    }

    /// The iCloud services used by the app.
    public class var iCloudServices: ICloudServices? {
        guard let iCloudServicesValue = shared.entitlements[EntitlementKey.iCloudServices.rawValue] as? String else {
            return nil
        }
        return .init(rawValue: iCloudServicesValue)
    }

    /// The container identifier to use for iCloud key-value storage.
    public class var iCloudKeyValueStoreIdentifier: String? {
        shared.entitlements[EntitlementKey.iCloudKeyValueStoreIdentifier.rawValue] as? String
    }

    #if os(iOS)
    /// A list of identifiers that specify pass types that the app can access in Wallet.
    public class var walletPassTypeIdentifiers: [String] {
        shared.entitlements[EntitlementKey.walletPassTypeIdentifiers.rawValue] as? [String] ?? []
    }

    /// A list of merchant IDs the app uses for Apple Pay support.
    public class var applePayMerchantIDs: [String] {
        shared.entitlements[EntitlementKey.applePayMerchantIDs.rawValue] as? [String] ?? []
    }
    #endif

    private init(_ entitlements: [String: Any]) {
        self.entitlements = entitlements
    }
}

private extension AppEntitlements {
    /// Keys used to get entitlement values from the app.
    ///
    /// This type contains a subset of the available application entitlement keys as described in the [Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements) documentation.
    ///
    /// Also see [SecEntitlements.h](https://opensource.apple.com/source/Security/Security-59306.140.5/sectask/SecEntitlements.h.auto.html) for undocumented entitlement keys.
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
        #if os(iOS)
        /// Entitlement key for the default data protection level of the app.
        ///
        /// See [Data Protection Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_developer_default-data-protection).
        case defaultDataProtection = "com.apple.developer.default-data-protection"
        #endif
        #if os(macOS)
        /// Entitlement key indicating if the app is sandboxed.
        ///
        /// The value of this key is a Boolean that indicates whether the app may use access control technology to contain damage to the system and user data if an app is compromised.
        ///
        /// See [App Sandbox Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_app-sandbox).
        case applicationSandbox = "com.apple.security.app-sandbox"
        #endif

        /// Entitlement key for the associated domains for specific services.
        ///
        /// See [Associated Domains Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_developer_associated-domains)
        case associatedDomains = "com.apple.developer.associated-domains"
        /// Entitlement key for the container identifiers for the iCloud development environment.
        ///
        /// See [com.apple.developer.icloud-container-development-container-identifiers](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_developer_icloud-container-development-container-identifiers)
        case iCouldContainerIdentifiers = "com.apple.developer.icloud-container-development-container-identifiers"
        /// Entitlement key for the environment to use for the iCloud containers.
        ///
        /// See [com.apple.developer.icloud-container-environment](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_developer_icloud-container-environment)
        case iCouldContainerEnvironment = "com.apple.developer.icloud-container-environment"
        /// Entitlement key for the iCloud services used by the app.
        ///
        /// See [iCloud Services Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_developer_icloud-services)
        case iCloudServices = "com.apple.developer.icloud-services"
        /// Entitlement key for the container identifier to use for iCloud key-value storage.
        ///
        /// See [iCloud Key-Value Store Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_developer_ubiquity-kvstore-identifier)
        case iCloudKeyValueStoreIdentifier = "com.apple.developer.ubiquity-kvstore-identifier"

        #if os(iOS)
        /// Entitlement key for the pass types that the app can access in Wallet.
        ///
        /// See [Pass Type IDs Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_developer_pass-type-identifiers)
        case walletPassTypeIdentifiers = "com.apple.developer.pass-type-identifiers"
        /// Entitlement key for the merchant IDs the app uses for Apple Pay support.
        ///
        /// See [Merchant IDs Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_developer_in-app-payments)
        case applePayMerchantIDs = "com.apple.developer.in-app-payments"
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

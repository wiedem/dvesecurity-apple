// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import CommonCrypto
import Foundation
import MachO

public extension AppEntitlements {
    private class func decodeEntitlements(from data: Data) throws -> [String: Any]? {
        return try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
    }

    /// Returns the embededd code signing entitlements from a bundle executable.
    class func executableCodeSigningEntitlements(of bundle: Bundle) throws -> [String: Any]? {
        guard let executableURL = bundle.executableURL else {
            throw AppEntitlementsError.noBundleExecutable
        }

        let executableData = try Data(contentsOf: executableURL, options: [.alwaysMapped])
        return try executableData.withUnsafeBytes { rawBufferPointer in
            var appEntitlements = [String: Any]()

            let machHeaderRawPointer = rawBufferPointer.baseAddress!

            // Get the entitlements from both the LC_CODE_SIGNATURE command and the Entitlements text section and merge them.
            if let codeSigningEntitlements = try embeddedCodeSigningEntitlements(from: machHeaderRawPointer, segmentOffset: 0) {
                appEntitlements.merge(codeSigningEntitlements) { current, _ in current }
            }
            if let textSectionEntitlements = try embeddedTextSectionEntitlements(from: machHeaderRawPointer) {
                appEntitlements.merge(textSectionEntitlements) { current, _ in current }
            }

            return appEntitlements.isEmpty ? nil : appEntitlements
        }
    }

    /// Returns the embededd code signing entitlements from the main program.
    class func embeddedCodeSigningEntitlements() throws -> [String: Any]? {
        guard let mainProgramHandle = dlopen(nil, RTLD_LAZY) else {
            let errorDescriptionPointer = dlerror()!
            throw AppEntitlementsError.failedToLoadLibrary(String(cString: errorDescriptionPointer))
        }
        defer { dlclose(mainProgramHandle) }

        guard let machHeaderRawPointer = dlsym(mainProgramHandle, MH_EXECUTE_SYM) else {
            let errorDescriptionPointer = dlerror()!
            throw AppEntitlementsError.failedToLoadExecutableSymbol(String(cString: errorDescriptionPointer))
        }
        guard let segPageZero = getsegbyname(SEG_PAGEZERO), let segLinkEdit = getsegbyname(SEG_LINKEDIT) else {
            throw AppEntitlementsError.invalidSegmentStructure
        }

        var appEntitlements = [String: Any]()

        // The LC_CODE_SIGNATURE command is inside the SEG_LINKEDIT segment, get the segment offset of this data segment.
        let linkEditSegmentOffset = Int(segLinkEdit.pointee.vmaddr - segPageZero.pointee.vmsize - segLinkEdit.pointee.fileoff)
        if let codeSigningEntitlements = try embeddedCodeSigningEntitlements(from: machHeaderRawPointer, segmentOffset: linkEditSegmentOffset) {
            appEntitlements.merge(codeSigningEntitlements) { current, _ in current }
        }

        if let textSectionEntitlements = try embeddedTextSectionEntitlements(from: machHeaderRawPointer) {
            appEntitlements.merge(textSectionEntitlements) { current, _ in current }
        }

        return appEntitlements.isEmpty ? nil : appEntitlements
    }

    internal class func embeddedCodeSigningEntitlements(from machHeaderRawPointer: UnsafeRawPointer, segmentOffset: Int) throws -> [String: Any]? {
        let (baseRawPointer, commandsPointer, commandsCount) = try MachOCodeSigning.getLoadCommands(from: machHeaderRawPointer)
        guard let codeSignatureCommand = MachOCodeSigning.findCodeSignatureCommand(from: commandsPointer, commandsCount: commandsCount) else {
            return nil
        }

        let codeSigningSuperBlobPointer = MachOCodeSigning.codeSigningSuperBlob(
            for: codeSignatureCommand,
            baseRawPointer: baseRawPointer,
            segmentOffset: segmentOffset
        )
        guard let magic = CodeSigningMagic(rawValue: codeSigningSuperBlobPointer.pointee.magic.bigEndian),
              magic == .embeddedSignature
        else {
            return nil
        }

        let codeSigningBlobs = MachOCodeSigning.codeSigningBlobs(for: codeSigningSuperBlobPointer)
        guard let embeddedEntitlementsBlob = codeSigningBlobs.first(where: { $0.magic == .embeddedEntitlements }) else {
            return nil
        }

        return try decodeEntitlements(from: embeddedEntitlementsBlob.data())
    }

    private class func embeddedTextSectionEntitlements() throws -> [String: Any]? {
        guard let mainProgramHandle = dlopen(nil, RTLD_LAZY) else {
            let errorDescriptionPointer = dlerror()!
            throw AppEntitlementsError.failedToLoadLibrary(String(cString: errorDescriptionPointer))
        }
        defer { dlclose(mainProgramHandle) }

        guard let machHeaderRawPointer = dlsym(mainProgramHandle, MH_EXECUTE_SYM) else {
            let errorDescriptionPointer = dlerror()!
            throw AppEntitlementsError.failedToLoadExecutableSymbol(String(cString: errorDescriptionPointer))
        }
        return try embeddedTextSectionEntitlements(from: machHeaderRawPointer)
    }

    internal class func embeddedTextSectionEntitlements(from machHeaderRawPointer: UnsafeRawPointer) throws -> [String: Any]? {
        let machHeaderMagic = machHeaderRawPointer.assumingMemoryBound(to: UInt32.self)
        let entitlementsData: Data

        switch machHeaderMagic.pointee {
        case MH_MAGIC:
            let machHeaderPointer = machHeaderRawPointer.assumingMemoryBound(to: mach_header.self)
            var sectionSize: UInt32 = 0
            guard let entitlementsSection = getsectdatafromheader(machHeaderPointer, SEG_TEXT, "__entitlements", &sectionSize) else {
                return nil
            }
            entitlementsData = Data(bytesNoCopy: entitlementsSection, count: Int(sectionSize), deallocator: .none)

        case MH_MAGIC_64:
            let machHeaderPointer = machHeaderRawPointer.assumingMemoryBound(to: mach_header_64.self)
            var sectionSize: UInt = 0
            guard let entitlementsSection = getsectiondata(machHeaderPointer, SEG_TEXT, "__entitlements", &sectionSize) else {
                return nil
            }
            entitlementsData = Data(bytesNoCopy: entitlementsSection, count: Int(sectionSize), deallocator: .none)

        case FAT_CIGAM, FAT_CIGAM_64:
            throw AppEntitlementsError.fatBinary

        default:
            throw AppEntitlementsError.invalidMachHeader
        }

        return try decodeEntitlements(from: entitlementsData)
    }
}

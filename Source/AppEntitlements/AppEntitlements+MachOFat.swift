// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import MachO

public extension AppEntitlements {
    static let processCpuType = getProcCpuType()

    class func fatExecutableCodeSigningEntitlements(
        of bundle: Bundle,
        cpuType: cpu_type_t = processCpuType,
        cpuSubType: cpu_subtype_t = CPU_SUBTYPE_ANY
    ) throws -> [String: Any]? {
        guard let executableURL = bundle.executableURL else {
            throw AppEntitlementsError.noBundleExecutable
        }

        let executableData = try Data(contentsOf: executableURL, options: [.alwaysMapped])
        return try executableData.withUnsafeBytes { rawBufferPointer in
            var appEntitlements = [String: Any]()

            let machHeaderRawPointer = rawBufferPointer.baseAddress!

            guard let archMachHeaderRawPointer = try findArchitectureMachHeader(
                fatMachHeaderRawPointer: machHeaderRawPointer,
                cpuType: cpuType,
                cpuSubType: cpuSubType
            ) else {
                throw AppEntitlementsError.invalidArchitecture
            }

            // Get the entitlements from both the LC_CODE_SIGNATURE command and the Entitlements text section and merge them.
            if let codeSigningEntitlements = try embeddedCodeSigningEntitlements(from: archMachHeaderRawPointer, segmentOffset: 0) {
                appEntitlements.merge(codeSigningEntitlements) { current, _ in current }
            }
            if let textSectionEntitlements = try embeddedTextSectionEntitlements(from: archMachHeaderRawPointer) {
                appEntitlements.merge(textSectionEntitlements) { current, _ in current }
            }

            return appEntitlements.isEmpty ? nil : appEntitlements
        }
    }

    private class func findArchitectureMachHeader(
        fatMachHeaderRawPointer: UnsafeRawPointer,
        cpuType: cpu_type_t,
        cpuSubType: cpu_subtype_t
    ) throws -> UnsafeRawPointer? {
        let fatHeaderPointer = fatMachHeaderRawPointer.assumingMemoryBound(to: fat_header.self)
        let fatArchitecturesRawPointer = UnsafeRawPointer(fatHeaderPointer.advanced(by: 1))
        let fatArchitecturesCount = Int(fatHeaderPointer.pointee.nfat_arch.bigEndian)
        var machHeaderRawPointer: UnsafeRawPointer?

        switch fatHeaderPointer.pointee.magic {
        case FAT_CIGAM:
            let archPointers = fatArchitecturesRawPointer.assumingMemoryBound(to: fat_arch.self)
            machHeaderRawPointer = (0..<fatArchitecturesCount)
                .first(where: {
                    archPointers[$0].cputype.bigEndian == cpuType &&
                        (cpuSubType == CPU_SUBTYPE_ANY || archPointers[$0].cpusubtype.bigEndian == cpuSubType)
                })
                .map { fatMachHeaderRawPointer + Int(archPointers[$0].offset.bigEndian) }

        case FAT_CIGAM_64:
            let archPointers = fatArchitecturesRawPointer.assumingMemoryBound(to: fat_arch_64.self)
            machHeaderRawPointer = (0..<fatArchitecturesCount)
                .first(where: {
                    archPointers[$0].cputype.bigEndian == cpuType &&
                        (cpuSubType == CPU_SUBTYPE_ANY || archPointers[$0].cpusubtype.bigEndian == cpuSubType)
                })
                .map { fatMachHeaderRawPointer + Int(archPointers[$0].offset.bigEndian) }

        default:
            throw AppEntitlementsError.invalidMachFatHeader
        }
        return machHeaderRawPointer
    }
}

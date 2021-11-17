// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation
import MachO

/// An error type for invalid code signatures.
public enum CodeSignatureError: Error {
    case invalidMachHeader
    case fatBinary
}

enum CodeSigningMagic: UInt32 {
    case singleRequirement = 0xFADE_0C00
    case requirementsVector = 0xFADE_0C01
    case codeDirectory = 0xFADE_0C02
    case embeddedSignature = 0xFADE_0CC0
    case detachedSignature = 0xFADE_0CC1
    case signedData = 0xFADE_0B01
    case embeddedEntitlements = 0xFADE_7171
}

struct CodeSigningSuperBlob {
    let magic: UInt32
    let totalLength: UInt32
    let indexEntriesCount: UInt32
}

struct CodeSigningBlobIndex {
    let type: UInt32
    let offset: UInt32
}

struct CodeSigningBlob {
    let magic: CodeSigningMagic
    let dataPointer: UnsafeRawPointer
    let dataLength: Int

    func data() -> Data {
        Data(bytes: dataPointer, count: dataLength)
    }
}

struct CodeSigningCodeDirectory {
    let magic: UInt32
    let length: UInt32
    let version: UInt32
    let flags: UInt32
    let hashOffset: UInt32
    let identOffset: UInt32
    let specialSlotsCount: UInt32
    let codeSlotsCount: UInt32
    let codeLimit: UInt32
    let hashSize: UInt8
    let hashType: UInt8
    let spare1: UInt8
    let pageSize: UInt8
    let spare2: UInt32
}

/// Based on the information published in Apple's open source `codesign` app.
///
/// For further details see [codesign.c](https://opensource.apple.com/source/Security/Security-59306.140.5/SecurityTool/sharedTool/codesign.c.auto.html).
final class MachOCodeSigning {
    class func getLoadCommands(from machHeaderRawPointer: UnsafeRawPointer) throws -> (UnsafeRawPointer, UnsafeRawPointer, UInt32) {
        let machHeaderMagic = machHeaderRawPointer.assumingMemoryBound(to: UInt32.self)
        let commandsPointer: UnsafeRawPointer
        let commandsCount: UInt32

        switch machHeaderMagic.pointee {
        case MH_MAGIC:
            let machHeaderPointer = machHeaderRawPointer.assumingMemoryBound(to: mach_header.self)
            commandsPointer = UnsafeRawPointer(machHeaderPointer.advanced(by: 1))
            commandsCount = machHeaderPointer.pointee.ncmds

        case MH_MAGIC_64:
            let machHeaderPointer = machHeaderRawPointer.assumingMemoryBound(to: mach_header_64.self)
            commandsPointer = UnsafeRawPointer(machHeaderPointer.advanced(by: 1))
            commandsCount = machHeaderPointer.pointee.ncmds

        case FAT_CIGAM, FAT_CIGAM_64:
            throw CodeSignatureError.fatBinary

        default:
            throw CodeSignatureError.invalidMachHeader
        }

        return (machHeaderRawPointer, commandsPointer, commandsCount)
    }

    class func findCodeSignatureCommand(from commands: UnsafeRawPointer, commandsCount: UInt32) -> UnsafePointer<load_command>? {
        var offset = 0

        for _ in 0..<commandsCount {
            let commandPointer = (commands + offset).assumingMemoryBound(to: load_command.self)
            guard commandPointer.pointee.cmd != LC_CODE_SIGNATURE else {
                return commandPointer
            }
            offset += Int(commandPointer.pointee.cmdsize)
        }
        return nil
    }

    class func codeSigningSuperBlob(
        for loadCommand: UnsafePointer<load_command>,
        baseRawPointer: UnsafeRawPointer,
        segmentOffset: Int
    ) -> UnsafePointer<CodeSigningSuperBlob> {
        let linkEditDataCommandPointer = UnsafeRawPointer(loadCommand).assumingMemoryBound(to: linkedit_data_command.self)
        return (baseRawPointer + segmentOffset + Int(linkEditDataCommandPointer.pointee.dataoff)).assumingMemoryBound(to: CodeSigningSuperBlob.self)
    }

    class func codeSigningBlobs(for codeSigningSuperBlob: UnsafePointer<CodeSigningSuperBlob>) -> [CodeSigningBlob] {
        let codeSigningSuperBlobRawPointer = UnsafeRawPointer(codeSigningSuperBlob)
        let indexEntriesRawPointer = UnsafeRawPointer(codeSigningSuperBlob.advanced(by: 1))
        let indexEntriesPointer = indexEntriesRawPointer.assumingMemoryBound(to: CodeSigningBlobIndex.self)
        let indexEntriesCount = Int(codeSigningSuperBlob.pointee.indexEntriesCount.bigEndian)

        var codeSigningBlobs = [CodeSigningBlob]()
        codeSigningBlobs.reserveCapacity(indexEntriesCount)

        for index in 0..<indexEntriesCount {
            // let blobType = indexEntriesPointer[index].type.bigEndian
            let blobOffset = Int(indexEntriesPointer[index].offset.bigEndian)
            let blobPointer = (codeSigningSuperBlobRawPointer + blobOffset)
            let blobMagicPointer = blobPointer.assumingMemoryBound(to: UInt32.self)
            guard let blobMagic = CodeSigningMagic(rawValue: blobMagicPointer.pointee.bigEndian) else {
                continue
            }

            let blobLengthPointer = blobMagicPointer.advanced(by: 1)
            let blobLength = blobLengthPointer.pointee.bigEndian
            let blobDataPointer = UnsafeRawPointer(blobLengthPointer.advanced(by: 1))
            let blobDataLength = Int(blobLength) - (blobDataPointer - blobPointer)

            let blob = CodeSigningBlob(magic: blobMagic, dataPointer: blobDataPointer, dataLength: blobDataLength)
            codeSigningBlobs.append(blob)
        }
        return codeSigningBlobs
    }
}

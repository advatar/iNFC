//
//  APDUCommand.swift
//  NFCPassportReader
//

import Foundation

@available(iOS 15, macOS 11, *)
enum APDUCommand {
    private static let instructionClass: UInt8 = 0x00
    private static let commandChainingInstructionClass: UInt8 = 0x10

    static var getChallenge: APDU {
        APDU(
            instructionClass: instructionClass,
            instructionCode: 0x84,
            p1Parameter: 0x00,
            p2Parameter: 0x00,
            data: Data(),
            expectedResponseLength: 8
        )
    }

    static func internalAuthentication(challenge: [UInt8], useExtendedMode: Bool) -> APDU {
        APDU(
            instructionClass: instructionClass,
            instructionCode: 0x88,
            p1Parameter: 0x00,
            p2Parameter: 0x00,
            data: Data(challenge),
            expectedResponseLength: useExtendedMode ? 65_535 : 256
        )
    }

    static func mutualAuthentication(data: Data) -> APDU {
        APDU(
            instructionClass: instructionClass,
            instructionCode: 0x82,
            p1Parameter: 0x00,
            p2Parameter: 0x00,
            data: data,
            expectedResponseLength: 256
        )
    }

    static func mseKeyAgreementTemplate(keyData: Data, idData: Data?) -> APDU {
        APDU(
            instructionClass: instructionClass,
            instructionCode: 0x22,
            p1Parameter: 0x41,
            p2Parameter: 0xA6,
            data: keyData + (idData ?? Data()),
            expectedResponseLength: 256
        )
    }

    static func mseSetATForInternalAuthentication(oid: String, keyId: Int?) -> APDU {
        let oidBytes = oidToBytes(oid: oid, replaceTag: true)

        let data: [UInt8]
        if let keyId, keyId != 0 {
            let keyIdBytes = wrapDO(b: 0x84, arr: intToBytes(val: keyId, removePadding: true))
            data = oidBytes + keyIdBytes
        } else {
            data = oidBytes
        }

        return APDU(
            instructionClass: instructionClass,
            instructionCode: 0x22,
            p1Parameter: 0x41,
            p2Parameter: 0xA4,
            data: Data(data),
            expectedResponseLength: 256
        )
    }

    static func mseSetATForMutualAuthentication(oid: String, keyType: UInt8) -> APDU {
        let data = oidToBytes(oid: oid, replaceTag: true) + wrapDO(b: 0x83, arr: [keyType])

        return APDU(
            instructionClass: instructionClass,
            instructionCode: 0x22,
            p1Parameter: 0xC1,
            p2Parameter: 0xA4,
            data: Data(data),
            expectedResponseLength: -1
        )
    }

    static func generalAuthenticate(wrappedData: Data, expectedResponseLength: Int, isLast: Bool) -> APDU {
        APDU(
            instructionClass: isLast ? instructionClass : commandChainingInstructionClass,
            instructionCode: 0x86,
            p1Parameter: 0x00,
            p2Parameter: 0x00,
            data: wrappedData,
            expectedResponseLength: expectedResponseLength
        )
    }

    static var selectMasterFile: APDU {
        APDU(
            instructionClass: instructionClass,
            instructionCode: 0xA4,
            p1Parameter: 0x00,
            p2Parameter: 0x0C,
            data: Data([0x3F, 0x00]),
            expectedResponseLength: -1
        )
    }

    static var selectPassportApplication: APDU {
        APDU(
            instructionClass: instructionClass,
            instructionCode: 0xA4,
            p1Parameter: 0x04,
            p2Parameter: 0x0C,
            data: Data([0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01]),
            expectedResponseLength: -1
        )
    }

    static func selectFile(_ fileId: [UInt8]) throws -> APDU {
        guard fileId.count == 2 else {
            throw NFCPassportReaderError.UnexpectedError
        }
        return APDU(
            instructionClass: instructionClass,
            instructionCode: 0xA4,
            p1Parameter: 0x02,
            p2Parameter: 0x0C,
            data: Data(fileId),
            expectedResponseLength: -1
        )
    }

    static func readBinaryHeader() throws -> APDU {
        APDU(
            instructionClass: instructionClass,
            instructionCode: 0xB0,
            p1Parameter: 0x00,
            p2Parameter: 0x00,
            data: Data(),
            expectedResponseLength: 4
        )
    }

    static func readBinary(offset: [UInt8], expectedResponseLength: Int) -> APDU {
        APDU(
            instructionClass: instructionClass,
            instructionCode: 0xB0,
            p1Parameter: offset[0],
            p2Parameter: offset[1],
            data: Data(),
            expectedResponseLength: expectedResponseLength
        )
    }

    static func getResponse(expectedResponseLength: Int) -> APDU {
        APDU(
            instructionClass: instructionClass,
            instructionCode: 0xC0,
            p1Parameter: 0x00,
            p2Parameter: 0x00,
            data: Data(),
            expectedResponseLength: expectedResponseLength
        )
    }
}

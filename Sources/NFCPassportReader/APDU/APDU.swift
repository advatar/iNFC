//
//  APDU.swift
//  NFCPassportReader
//
//  Created by OpenAI Codex on 21/04/2026.
//

import Foundation

struct APDU: Equatable, CustomStringConvertible {
    let instructionClass: UInt8
    let instructionCode: UInt8
    let p1Parameter: UInt8
    let p2Parameter: UInt8
    let data: Data
    let expectedResponseLength: Int

    init(
        instructionClass: UInt8,
        instructionCode: UInt8,
        p1Parameter: UInt8,
        p2Parameter: UInt8,
        data: Data = Data(),
        expectedResponseLength: Int = -1
    ) {
        self.instructionClass = instructionClass
        self.instructionCode = instructionCode
        self.p1Parameter = p1Parameter
        self.p2Parameter = p2Parameter
        self.data = data
        self.expectedResponseLength = expectedResponseLength
    }

    init?(data encodedData: Data) {
        let bytes = [UInt8](encodedData)
        guard bytes.count >= 4 else {
            return nil
        }

        instructionClass = bytes[0]
        instructionCode = bytes[1]
        p1Parameter = bytes[2]
        p2Parameter = bytes[3]

        guard bytes.count > 4 else {
            data = Data()
            expectedResponseLength = -1
            return
        }

        let lengthByte = bytes[4]
        if bytes.count == 5 {
            data = Data()
            expectedResponseLength = Int(lengthByte)
            return
        }

        if lengthByte == 0x00 {
            guard bytes.count >= 7 else {
                return nil
            }

            if bytes.count == 7 {
                data = Data()
                expectedResponseLength = APDU.extendedLength(from: bytes[5], bytes[6])
                return
            }

            let dataLength = APDU.extendedLength(from: bytes[5], bytes[6])
            let dataStartIndex = 7
            let dataEndIndex = dataStartIndex + dataLength
            guard dataEndIndex <= bytes.count else {
                return nil
            }

            data = Data(bytes[dataStartIndex..<dataEndIndex])

            if dataEndIndex == bytes.count {
                expectedResponseLength = -1
            } else if dataEndIndex + 2 == bytes.count {
                expectedResponseLength = APDU.extendedLength(from: bytes[dataEndIndex], bytes[dataEndIndex + 1])
            } else {
                return nil
            }
        } else {
            let dataLength = Int(lengthByte)
            let dataStartIndex = 5
            let dataEndIndex = dataStartIndex + dataLength
            guard dataEndIndex <= bytes.count else {
                return nil
            }

            data = Data(bytes[dataStartIndex..<dataEndIndex])

            if dataEndIndex == bytes.count {
                expectedResponseLength = -1
            } else if dataEndIndex + 1 == bytes.count {
                expectedResponseLength = Int(bytes[dataEndIndex])
            } else {
                return nil
            }
        }
    }

    var description: String {
        "APDU(cla: \(hex(instructionClass)), ins: \(hex(instructionCode)), p1: \(hex(p1Parameter)), p2: \(hex(p2Parameter)), data: \(binToHexRep([UInt8](data))), le: \(expectedResponseLength))"
    }
}

private extension APDU {
    static func extendedLength(from highByte: UInt8, _ lowByte: UInt8) -> Int {
        (Int(highByte) << 8) | Int(lowByte)
    }

    func hex(_ byte: UInt8) -> String {
        "0x" + binToHexRep(byte)
    }
}

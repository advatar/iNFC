//
//  APDUTransport.swift
//  NFCPassportReader
//
//  Created by OpenAI Codex on 21/04/2026.
//

import Foundation

@available(iOS 15, macOS 11, *)
struct APDUTransportResponse {
    let data: Data
    let sw1: UInt8
    let sw2: UInt8
}

@available(iOS 15, macOS 11, *)
protocol APDUTransport {
    func send(_ apdu: APDU) async throws -> APDUTransportResponse
}

#if canImport(CoreNFC)
import CoreNFC

@available(iOS 15, *)
struct CoreNFCAPDUTransport: APDUTransport {
    private let tag: NFCISO7816Tag

    init(tag: NFCISO7816Tag) {
        self.tag = tag
    }

    func send(_ apdu: APDU) async throws -> APDUTransportResponse {
        let coreNFCAPDU = NFCISO7816APDU(apdu: apdu)
        let (data, sw1, sw2) = try await tag.sendCommand(apdu: coreNFCAPDU)
        return APDUTransportResponse(data: data, sw1: sw1, sw2: sw2)
    }
}

@available(iOS 15, *)
private extension NFCISO7816APDU {
    convenience init(apdu: APDU) {
        self.init(
            instructionClass: apdu.instructionClass,
            instructionCode: apdu.instructionCode,
            p1Parameter: apdu.p1Parameter,
            p2Parameter: apdu.p2Parameter,
            data: apdu.data,
            expectedResponseLength: apdu.expectedResponseLength
        )
    }
}

#endif

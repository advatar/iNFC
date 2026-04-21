import Foundation
import XCTest

@testable import NFCPassportReader

@available(iOS 15, macOS 11, *)
final class TagReaderTransportTests: XCTestCase {
    func testSendReadsGetResponseContinuation() async throws {
        let transport = ScriptedAPDUTransport(responses: [
            APDUTransportResponse(data: Data([0xAA]), sw1: 0x61, sw2: 0x02),
            APDUTransportResponse(data: Data([0xBB, 0xCC]), sw1: 0x90, sw2: 0x00)
        ])
        let reader = TagReader(transport: transport)

        let response = try await reader.send(cmd: APDUCommand.getChallenge)

        XCTAssertEqual(response.data, [0xAA, 0xBB, 0xCC])
        XCTAssertEqual(transport.sentInstructions, [0x84, 0xC0])
    }

    func testReadDataGroupSelectsFileAndReadsRemainingBytes() async throws {
        let transport = ScriptedAPDUTransport(responses: [
            APDUTransportResponse(data: Data(), sw1: 0x90, sw2: 0x00),
            APDUTransportResponse(data: Data([0x60, 0x03, 0xAA, 0xBB]), sw1: 0x90, sw2: 0x00),
            APDUTransportResponse(data: Data([0xAA, 0xBB, 0xCC]), sw1: 0x90, sw2: 0x00)
        ])
        let reader = TagReader(transport: transport)

        let data = try await reader.readDataGroup(dataGroup: .COM)

        XCTAssertEqual(data, [0x60, 0x03, 0xAA, 0xBB, 0xCC])
        XCTAssertEqual(transport.sentInstructions, [0xA4, 0xB0, 0xB0])
        XCTAssertEqual(transport.sentCommands[0].data, Data([0x01, 0x1E]))
        XCTAssertEqual(transport.sentCommands[2].expectedResponseLength, 3)
    }
}

@available(iOS 15, macOS 11, *)
private final class ScriptedAPDUTransport: APDUTransport {
    private var responses: [APDUTransportResponse]
    private(set) var sentCommands: [APDU] = []

    var sentInstructions: [UInt8] {
        sentCommands.map(\.instructionCode)
    }

    init(responses: [APDUTransportResponse]) {
        self.responses = responses
    }

    func send(_ apdu: APDU) async throws -> APDUTransportResponse {
        sentCommands.append(apdu)

        guard !responses.isEmpty else {
            throw NFCPassportReaderError.UnexpectedError
        }

        return responses.removeFirst()
    }
}

#if canImport(CoreNFC)
import CoreNFC
import XCTest

@testable import NFCPassportReader

@available(iOS 15, *)
final class APDUCommandTests: XCTestCase {
    func testGetChallengeBuildsExpectedCommand() {
        let command = APDUCommand.getChallenge

        XCTAssertEqual(command.instructionClass, 0x00)
        XCTAssertEqual(command.instructionCode, 0x84)
        XCTAssertEqual(command.p1Parameter, 0x00)
        XCTAssertEqual(command.p2Parameter, 0x00)
        XCTAssertEqual(command.expectedResponseLength, 8)
    }

    func testSelectPassportApplicationBuildsExpectedAIDCommand() {
        let command = APDUCommand.selectPassportApplication

        XCTAssertEqual(command.instructionClass, 0x00)
        XCTAssertEqual(command.instructionCode, 0xA4)
        XCTAssertEqual(command.p1Parameter, 0x04)
        XCTAssertEqual(command.p2Parameter, 0x0C)
        XCTAssertEqual(command.data, Data([0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01]))
        XCTAssertEqual(command.expectedResponseLength, -1)
    }

    func testGeneralAuthenticateUsesCommandChainingUntilLastCommand() {
        let chained = APDUCommand.generalAuthenticate(
            wrappedData: Data([0x7C, 0x00]),
            expectedResponseLength: 256,
            isLast: false
        )
        let last = APDUCommand.generalAuthenticate(
            wrappedData: Data([0x7C, 0x00]),
            expectedResponseLength: 256,
            isLast: true
        )

        XCTAssertEqual(chained.instructionClass, 0x10)
        XCTAssertEqual(last.instructionClass, 0x00)
        XCTAssertEqual(chained.instructionCode, 0x86)
        XCTAssertEqual(last.instructionCode, 0x86)
    }
}
#endif

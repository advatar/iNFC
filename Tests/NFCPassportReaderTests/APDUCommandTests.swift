import XCTest

@testable import NFCPassportReader

@available(iOS 15, *)
final class APDUCommandTests: XCTestCase {
    func testAPDUParsesShortEncodedCommand() {
        let command = APDU(data: Data([0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x1E, 0x00]))

        XCTAssertEqual(command?.instructionClass, 0x00)
        XCTAssertEqual(command?.instructionCode, 0xA4)
        XCTAssertEqual(command?.p1Parameter, 0x02)
        XCTAssertEqual(command?.p2Parameter, 0x0C)
        XCTAssertEqual(command?.data, Data([0x01, 0x1E]))
        XCTAssertEqual(command?.expectedResponseLength, 0)
    }

    func testAPDUParsesExtendedResponseLength() {
        let command = APDU(data: Data([0x00, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x04]))

        XCTAssertEqual(command?.instructionCode, 0xB0)
        XCTAssertEqual(command?.data, Data())
        XCTAssertEqual(command?.expectedResponseLength, 4)
    }

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

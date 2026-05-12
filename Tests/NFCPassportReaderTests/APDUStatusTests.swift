import XCTest

@testable import NFCPassportReader

final class APDUStatusTests: XCTestCase {
    func testSuccessRequiresBothStatusBytesToMatch() {
        XCTAssertTrue(APDUStatus(sw1: 0x90, sw2: 0x00).isSuccess)
        XCTAssertFalse(APDUStatus(sw1: 0x90, sw2: 0x01).isSuccess)
        XCTAssertFalse(APDUStatus(sw1: 0x63, sw2: 0x00).isSuccess)
    }

    func testInvalidSecretCodeMapsToInvalidMRZKey() {
        let response = ResponseAPDU(data: [], sw1: 0x63, sw2: 0x00)

        XCTAssertThrowsError(try response.ensureSuccess()) { error in
            guard case NFCPassportReaderError.InvalidMRZKey = error else {
                return XCTFail("Expected InvalidMRZKey, got \(error)")
            }
        }
    }

    func testKnownAPDUErrorPreservesExistingMessageText() {
        let response = ResponseAPDU(data: [], sw1: 0x69, sw2: 0x82)

        XCTAssertThrowsError(try response.ensureSuccess()) { error in
            guard case NFCPassportReaderError.ResponseError(let reason, let sw1, let sw2) = error else {
                return XCTFail("Expected ResponseError, got \(error)")
            }

            XCTAssertEqual(reason, "Security status not satisfied")
            XCTAssertEqual(sw1, 0x69)
            XCTAssertEqual(sw2, 0x82)
        }
    }
}

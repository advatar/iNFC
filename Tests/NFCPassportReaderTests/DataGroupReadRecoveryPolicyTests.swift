import XCTest

@testable import NFCPassportReader

final class DataGroupReadRecoveryPolicyTests: XCTestCase {
    func testClassNotSupportedFailsWithoutChipAuthentication() {
        XCTAssertEqual(action(for: 0x6E, 0x00, hasChipAuthentication: false), .fail)
    }

    func testClassNotSupportedResetsChipAuthenticationBeforeBACWhenChipAuthenticationIsActive() {
        XCTAssertEqual(action(for: 0x6E, 0x00, hasChipAuthentication: true), .resetChipAuthenticationAndRedoBAC)
    }

    func testSecurityStatusNotSatisfiedRemovesRequestedDataGroupBeforeBAC() {
        XCTAssertEqual(action(for: 0x69, 0x82), .removeRequestedDataGroupAndRedoBAC)
    }

    func testFileNotFoundRemovesRequestedDataGroupBeforeBAC() {
        XCTAssertEqual(action(for: 0x6A, 0x82), .removeRequestedDataGroupAndRedoBAC)
    }

    func testIncorrectSecureMessagingDataObjectsRedoBAC() {
        XCTAssertEqual(action(for: 0x69, 0x88), .redoBAC)
    }

    func testWrongLengthReducesReadLengthBeforeBAC() {
        XCTAssertEqual(action(for: 0x67, 0x00), .reduceReadLengthAndRedoBAC)
        XCTAssertEqual(action(for: 0x6C, 0x20), .reduceReadLengthAndRedoBAC)
    }

    func testEndOfFileReducesReadLengthBeforeBAC() {
        XCTAssertEqual(action(for: 0x62, 0x82), .reduceReadLengthAndRedoBAC)
    }

    func testUnsupportedDataGroupSkipsDataGroup() {
        XCTAssertEqual(
            DataGroupReadRecoveryPolicy.action(for: .UnsupportedDataGroup, hasChipAuthentication: false),
            .skipDataGroup
        )
    }

    func testUncategorizedErrorRetries() {
        XCTAssertEqual(action(for: 0x6A, 0x88), .retry)
    }

    private func action(
        for sw1: UInt8,
        _ sw2: UInt8,
        hasChipAuthentication: Bool = false
    ) -> DataGroupReadRecoveryAction {
        DataGroupReadRecoveryPolicy.action(
            for: .ResponseError("localized text should not drive recovery", sw1, sw2),
            hasChipAuthentication: hasChipAuthentication
        )
    }
}

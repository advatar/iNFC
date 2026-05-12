import XCTest

@testable import NFCPassportReader

@available(iOS 13, macOS 10.15, *)
final class ChipAuthenticationInfoTests: XCTestCase {
    func testSupportedChipAuthenticationProtocolOIDAttributes() throws {
        let cases: [(oid: String, name: String, agreement: String, cipher: String, keyLength: Int)] = [
            (SecurityInfo.ID_CA_DH_3DES_CBC_CBC_OID, "id-CA-DH-3DES-CBC-CBC", "DH", "DESede", 128),
            (SecurityInfo.ID_CA_DH_AES_CBC_CMAC_128_OID, "id-CA-DH-AES-CBC-CMAC-128", "DH", "AES", 128),
            (SecurityInfo.ID_CA_DH_AES_CBC_CMAC_192_OID, "id-CA-DH-AES-CBC-CMAC-192", "DH", "AES", 192),
            (SecurityInfo.ID_CA_DH_AES_CBC_CMAC_256_OID, "id-CA-DH-AES-CBC-CMAC-256", "DH", "AES", 256),
            (SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC_OID, "id-CA-ECDH-3DES-CBC-CBC", "ECDH", "DESede", 128),
            (SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128_OID, "id-CA-ECDH-AES-CBC-CMAC-128", "ECDH", "AES", 128),
            (SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_192_OID, "id-CA-ECDH-AES-CBC-CMAC-192", "ECDH", "AES", 192),
            (SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_256_OID, "id-CA-ECDH-AES-CBC-CMAC-256", "ECDH", "AES", 256)
        ]

        for testCase in cases {
            let info = ChipAuthenticationInfo(oid: testCase.oid, version: 1, keyId: 2)

            XCTAssertTrue(ChipAuthenticationInfo.checkRequiredIdentifier(testCase.oid), testCase.oid)
            XCTAssertEqual(try ChipAuthenticationInfo.toKeyAgreementAlgorithm(oid: testCase.oid), testCase.agreement, testCase.oid)
            XCTAssertEqual(try ChipAuthenticationInfo.toCipherAlgorithm(oid: testCase.oid), testCase.cipher, testCase.oid)
            XCTAssertEqual(try ChipAuthenticationInfo.toKeyLength(oid: testCase.oid), testCase.keyLength, testCase.oid)
            XCTAssertEqual(info.getProtocolOIDString(), testCase.name, testCase.oid)
            XCTAssertEqual(info.getKeyId(), 2)
        }
    }

    func testChipAuthenticationRejectsUnknownProtocolOID() {
        let oid = "0.4.0.127.0.7.2.2.3.99.99"

        XCTAssertFalse(ChipAuthenticationInfo.checkRequiredIdentifier(oid))
        XCTAssertThrowsError(try ChipAuthenticationInfo.toKeyAgreementAlgorithm(oid: oid))
        XCTAssertThrowsError(try ChipAuthenticationInfo.toCipherAlgorithm(oid: oid))
        XCTAssertThrowsError(try ChipAuthenticationInfo.toKeyLength(oid: oid))
    }

    func testChipAuthenticationPublicKeyProtocolNamesAndDefaultKeyId() {
        let key = NativeSubjectPublicKey(der: [])
        let dh = ChipAuthenticationPublicKeyInfo(oid: SecurityInfo.ID_PK_DH_OID, pubKey: key)
        let ecdh = ChipAuthenticationPublicKeyInfo(oid: SecurityInfo.ID_PK_ECDH_OID, pubKey: key, keyId: 7)

        XCTAssertTrue(ChipAuthenticationPublicKeyInfo.checkRequiredIdentifier(SecurityInfo.ID_PK_DH_OID))
        XCTAssertTrue(ChipAuthenticationPublicKeyInfo.checkRequiredIdentifier(SecurityInfo.ID_PK_ECDH_OID))
        XCTAssertFalse(ChipAuthenticationPublicKeyInfo.checkRequiredIdentifier("1.2.3.4"))
        XCTAssertEqual(dh.getProtocolOIDString(), "id-PK-DH")
        XCTAssertEqual(ecdh.getProtocolOIDString(), "id-PK-ECDH")
        XCTAssertEqual(dh.getKeyId(), 0)
        XCTAssertEqual(ecdh.getKeyId(), 7)
    }
}

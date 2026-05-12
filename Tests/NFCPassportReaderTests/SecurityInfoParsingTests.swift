import XCTest

@testable import NFCPassportReader

@available(iOS 13, macOS 10.15, *)
final class SecurityInfoParsingTests: XCTestCase {
    func testCardAccessParsesPACEInfo() throws {
        let paceInfo = try derSequence(
            oidToBytes(oid: SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, replaceTag: false)
                + derInteger(2)
                + derInteger(UInt8(PACEInfo.PARAM_ID_ECP_NIST_P256_R1))
        )
        let cardAccess = try CardAccess(derSet(paceInfo))

        XCTAssertEqual(cardAccess.securityInfos.count, 1)
        let parsedPACEInfo = try XCTUnwrap(cardAccess.paceInfo)
        XCTAssertEqual(parsedPACEInfo.getObjectIdentifier(), SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128)
        XCTAssertEqual(parsedPACEInfo.getVersion(), 2)
        XCTAssertEqual(parsedPACEInfo.getParameterId(), PACEInfo.PARAM_ID_ECP_NIST_P256_R1)
        XCTAssertEqual(try parsedPACEInfo.getMappingType(), .GM)
        XCTAssertEqual(try parsedPACEInfo.getKeyAgreementAlgorithm(), "ECDH")
    }

    func testDataGroup14ParsesChipAuthenticationInfo() throws {
        let chipAuthenticationInfo = try derSequence(
            oidToBytes(oid: SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_256_OID, replaceTag: false)
                + derInteger(1)
                + derInteger(2)
        )
        let body = try derSet(chipAuthenticationInfo)
        let dg14 = try DataGroup14([0x6E] + toAsn1Length(body.count) + body)

        XCTAssertEqual(dg14.securityInfos.count, 1)
        let parsedInfo = try XCTUnwrap(dg14.securityInfos.first as? ChipAuthenticationInfo)
        XCTAssertEqual(parsedInfo.getObjectIdentifier(), SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_256_OID)
        XCTAssertEqual(parsedInfo.getProtocolOIDString(), "id-CA-ECDH-AES-CBC-CMAC-256")
        XCTAssertEqual(parsedInfo.getKeyId(), 2)
        XCTAssertEqual(try ChipAuthenticationInfo.toKeyAgreementAlgorithm(oid: parsedInfo.getObjectIdentifier()), "ECDH")
        XCTAssertEqual(try ChipAuthenticationInfo.toKeyLength(oid: parsedInfo.getObjectIdentifier()), 256)
    }

    func testDataGroup14ParsesChipAuthenticationPublicKeyInfoThroughCryptoProvider() throws {
        let subjectPublicKeyInfo = hexRepToBin("""
            308201333081EC06072A8648CE3D02013081E0020101302C06072A8648CE3D0101022100
            A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E537730440420
            7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9042026D
            C5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B60441048B
            D2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262547EF835
            C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997022100A9FB57DBA1
            EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7020101034200049BD
            24313046EB43CC4652B6FC1AA00E76B5405F4E7016521E95BE53B9C5BAE5A1410F12C
            F3AE23F886EFCEDE89F7C63AD9CA9E5C6C05DE902DB70F2EB2341F9D
            """.filter { !$0.isWhitespace })
        let publicKeyInfo = try derSequence(
            oidToBytes(oid: SecurityInfo.ID_PK_ECDH_OID, replaceTag: false)
                + subjectPublicKeyInfo
                + derInteger(3)
        )
        let body = try derSet(publicKeyInfo)
        let dg14 = try DataGroup14([0x6E] + toAsn1Length(body.count) + body)

        XCTAssertEqual(dg14.securityInfos.count, 1)
        let parsedInfo = try XCTUnwrap(dg14.securityInfos.first as? ChipAuthenticationPublicKeyInfo)
        XCTAssertEqual(parsedInfo.getObjectIdentifier(), SecurityInfo.ID_PK_ECDH_OID)
        XCTAssertEqual(parsedInfo.getProtocolOIDString(), "id-PK-ECDH")
        XCTAssertEqual(parsedInfo.getKeyId(), 3)
    }

    private func derSequence(_ value: [UInt8]) throws -> [UInt8] {
        try [0x30] + toAsn1Length(value.count) + value
    }

    private func derSet(_ value: [UInt8]) throws -> [UInt8] {
        try [0x31] + toAsn1Length(value.count) + value
    }

    private func derInteger(_ value: UInt8) -> [UInt8] {
        [0x02, 0x01, value]
    }
}

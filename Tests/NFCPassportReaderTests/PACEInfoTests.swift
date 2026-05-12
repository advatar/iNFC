import XCTest

@testable import NFCPassportReader

@available(iOS 13, macOS 10.15, *)
final class PACEInfoTests: XCTestCase {
    func testSupportedPACEProtocolOIDAttributes() throws {
        let cases: [(oid: String, name: String, mapping: PACEMappingType, agreement: String, cipher: String, digest: String, keyLength: Int)] = [
            (SecurityInfo.ID_PACE_DH_GM_3DES_CBC_CBC, "id-PACE-DH-GM-3DES-CBC-CBC", .GM, "DH", "DESede", "SHA-1", 128),
            (SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128, "id-PACE-DH-GM-AES-CBC-CMAC-128", .GM, "DH", "AES", "SHA-1", 128),
            (SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_192, "id-PACE-DH-GM-AES-CBC-CMAC-192", .GM, "DH", "AES", "SHA-256", 192),
            (SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_256, "id-PACE-DH-GM-AES-CBC-CMAC-256", .GM, "DH", "AES", "SHA-256", 256),
            (SecurityInfo.ID_PACE_DH_IM_3DES_CBC_CBC, "id-PACE-DH-IM-3DES-CBC-CBC", .IM, "DH", "DESede", "SHA-1", 128),
            (SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_128, "id-PACE-DH-IM-AES-CBC-CMAC-128", .IM, "DH", "AES", "SHA-1", 128),
            (SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_192, "id-PACE-DH-IM-AES-CBC-CMAC-192", .IM, "DH", "AES", "SHA-256", 192),
            (SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_256, "id-PACE-DH-IM-AES-CBC-CMAC-256", .IM, "DH", "AES", "SHA-256", 256),
            (SecurityInfo.ID_PACE_ECDH_GM_3DES_CBC_CBC, "id-PACE-ECDH-GM-3DES-CBC-CBC", .GM, "ECDH", "DESede", "SHA-1", 128),
            (SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, "id-PACE-ECDH-GM-AES-CBC-CMAC-128", .GM, "ECDH", "AES", "SHA-1", 128),
            (SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_192, "id-PACE-ECDH-GM-AES-CBC-CMAC-192", .GM, "ECDH", "AES", "SHA-256", 192),
            (SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256, "id-PACE-ECDH-GM-AES-CBC-CMAC-256", .GM, "ECDH", "AES", "SHA-256", 256),
            (SecurityInfo.ID_PACE_ECDH_IM_3DES_CBC_CBC, "id-PACE-ECDH-IM-3DES-CBC-CBC", .IM, "ECDH", "DESede", "SHA-1", 128),
            (SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_128, "id-PACE-ECDH-IM-AES-CBC-CMAC-128", .IM, "ECDH", "AES", "SHA-1", 128),
            (SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_192, "id-PACE-ECDH-IM-AES-CBC-CMAC-192", .IM, "ECDH", "AES", "SHA-256", 192),
            (SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_256, "id-PACE-ECDH-IM-AES-CBC-CMAC-256", .IM, "ECDH", "AES", "SHA-256", 256),
            (SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128, "id-PACE-ECDH-CAM-AES-CBC-CMAC-128", .CAM, "ECDH", "AES", "SHA-1", 128),
            (SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_192, "id-PACE-ECDH-CAM-AES-CBC-CMAC-192", .CAM, "ECDH", "AES", "SHA-256", 192),
            (SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_256, "id-PACE-ECDH-CAM-AES-CBC-CMAC-256", .CAM, "ECDH", "AES", "SHA-256", 256)
        ]

        XCTAssertEqual(Set(PACEInfo.allowedIdentifiers), Set(cases.map(\.oid)))

        for testCase in cases {
            let info = PACEInfo(oid: testCase.oid, version: 2, parameterId: PACEInfo.PARAM_ID_ECP_NIST_P256_R1)

            XCTAssertTrue(PACEInfo.checkRequiredIdentifier(testCase.oid), testCase.oid)
            XCTAssertEqual(try PACEInfo.toMappingType(oid: testCase.oid), testCase.mapping, testCase.oid)
            XCTAssertEqual(try PACEInfo.toKeyAgreementAlgorithm(oid: testCase.oid), testCase.agreement, testCase.oid)
            XCTAssertEqual(try PACEInfo.toCipherAlgorithm(oid: testCase.oid), testCase.cipher, testCase.oid)
            XCTAssertEqual(try PACEInfo.toDigestAlgorithm(oid: testCase.oid), testCase.digest, testCase.oid)
            XCTAssertEqual(try PACEInfo.toKeyLength(oid: testCase.oid), testCase.keyLength, testCase.oid)
            XCTAssertEqual(info.getProtocolOIDString(), testCase.name, testCase.oid)
        }
    }

    func testPACERejectsUnknownProtocolOID() {
        let oid = "0.4.0.127.0.7.2.2.4.99.99"

        XCTAssertFalse(PACEInfo.checkRequiredIdentifier(oid))
        XCTAssertThrowsError(try PACEInfo.toMappingType(oid: oid))
        XCTAssertThrowsError(try PACEInfo.toKeyAgreementAlgorithm(oid: oid))
        XCTAssertThrowsError(try PACEInfo.toCipherAlgorithm(oid: oid))
        XCTAssertThrowsError(try PACEInfo.toDigestAlgorithm(oid: oid))
        XCTAssertThrowsError(try PACEInfo.toKeyLength(oid: oid))
    }

    func testAllPACEStandardizedDomainParametersAreRecognized() {
        let parameterIds = [
            PACEInfo.PARAM_ID_GFP_1024_160,
            PACEInfo.PARAM_ID_GFP_2048_224,
            PACEInfo.PARAM_ID_GFP_2048_256,
            PACEInfo.PARAM_ID_ECP_NIST_P192_R1,
            PACEInfo.PARAM_ID_ECP_BRAINPOOL_P192_R1,
            PACEInfo.PARAM_ID_ECP_NIST_P224_R1,
            PACEInfo.PARAM_ID_ECP_BRAINPOOL_P224_R1,
            PACEInfo.PARAM_ID_ECP_NIST_P256_R1,
            PACEInfo.PARAM_ID_ECP_BRAINPOOL_P256_R1,
            PACEInfo.PARAM_ID_ECP_BRAINPOOL_P320_R1,
            PACEInfo.PARAM_ID_ECP_NIST_P384_R1,
            PACEInfo.PARAM_ID_ECP_BRAINPOOL_P384_R1,
            PACEInfo.PARAM_ID_ECP_BRAINPOOL_P512_R1,
            PACEInfo.PARAM_ID_ECP_NIST_P521_R1
        ]

        for parameterId in parameterIds {
            XCTAssertNoThrow(try PACEInfo.getParameterSpec(stdDomainParam: parameterId), "parameterId \(parameterId)")
        }

        XCTAssertThrowsError(try PACEInfo.getParameterSpec(stdDomainParam: 99))
    }
}

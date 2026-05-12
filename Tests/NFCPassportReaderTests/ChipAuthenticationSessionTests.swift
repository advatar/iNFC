import XCTest

@testable import NFCPassportReader

@available(iOS 13, macOS 10.15, *)
final class ChipAuthenticationSessionTests: XCTestCase {
    func testAuthenticationOIDResolutionPrefersMatchingChipAuthenticationInfo() {
        let key = NativeSubjectPublicKey(der: [])
        let publicKeyInfo = ChipAuthenticationPublicKeyInfo(
            oid: SecurityInfo.ID_PK_ECDH_OID,
            pubKey: key,
            keyId: 7
        )
        let authenticationInfo = ChipAuthenticationInfo(
            oid: SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_256_OID,
            version: 1,
            keyId: 7
        )

        XCTAssertEqual(
            ChipAuthenticationSession.authenticationOID(
                for: publicKeyInfo,
                authenticationInfosByKeyId: [authenticationInfo.getKeyId(): authenticationInfo]
            ),
            SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_256_OID
        )
    }

    func testAuthenticationOIDResolutionFallsBackToPublicKeyOID() {
        let key = NativeSubjectPublicKey(der: [])
        let dh = ChipAuthenticationPublicKeyInfo(oid: SecurityInfo.ID_PK_DH_OID, pubKey: key)
        let ecdh = ChipAuthenticationPublicKeyInfo(oid: SecurityInfo.ID_PK_ECDH_OID, pubKey: key)
        let unsupported = ChipAuthenticationPublicKeyInfo(oid: "1.2.3.4", pubKey: key)

        XCTAssertEqual(
            ChipAuthenticationSession.authenticationOID(for: dh, authenticationInfosByKeyId: [:]),
            SecurityInfo.ID_CA_DH_3DES_CBC_CBC_OID
        )
        XCTAssertEqual(
            ChipAuthenticationSession.authenticationOID(for: ecdh, authenticationInfosByKeyId: [:]),
            SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC_OID
        )
        XCTAssertNil(ChipAuthenticationSession.authenticationOID(for: unsupported, authenticationInfosByKeyId: [:]))
    }

    func testKeyAgreementTemplateDataWrapsPublicKeyAndOptionalKeyId() {
        let withoutKeyId = ChipAuthenticationSession.keyAgreementTemplateData(
            publicKeyData: [0xAA, 0xBB, 0xCC],
            keyId: nil
        )
        let withKeyId = ChipAuthenticationSession.keyAgreementTemplateData(
            publicKeyData: [0xAA, 0xBB, 0xCC],
            keyId: 2
        )

        XCTAssertEqual([UInt8](withoutKeyId.keyData), hexRepToBin("9103AABBCC"))
        XCTAssertNil(withoutKeyId.idData)
        XCTAssertEqual([UInt8](withKeyId.keyData), hexRepToBin("9103AABBCC"))
        XCTAssertEqual(withKeyId.idData.map { [UInt8]($0) }, hexRepToBin("840102"))
    }

    func testGeneralAuthenticateDataWrapsPublicKey() {
        XCTAssertEqual(
            ChipAuthenticationSession.generalAuthenticateData(publicKeyData: [0xAA, 0xBB]),
            hexRepToBin("8002AABB")
        )
    }

    func testChunksUseChipAuthenticationCommandChainingSize() {
        let data = (0..<500).map { UInt8($0 % 256) }
        let chunks = ChipAuthenticationSession.chunks(of: data)

        XCTAssertEqual(chunks.map(\.count), [224, 224, 52])
        XCTAssertEqual(chunks.flatMap { $0 }, data)
    }

    func testSecureMessagingKeysUseCAProtocolCipherAndKeyLength() throws {
        let sharedSecret = hexRepToBin("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF")
        let generator = SecureMessagingSessionKeyGenerator()

        let aesKeys = try ChipAuthenticationSession.secureMessagingKeys(
            oid: SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_256_OID,
            sharedSecret: sharedSecret
        )
        XCTAssertEqual(aesKeys.encryptionAlgorithm, .AES)
        XCTAssertEqual(aesKeys.ksEnc, try generator.deriveKey(keySeed: sharedSecret, cipherAlgName: "AES", keyLength: 256, mode: .ENC_MODE))
        XCTAssertEqual(aesKeys.ksMac, try generator.deriveKey(keySeed: sharedSecret, cipherAlgName: "AES", keyLength: 256, mode: .MAC_MODE))
        XCTAssertEqual(aesKeys.ssc, [UInt8](repeating: 0, count: 8))

        let desKeys = try ChipAuthenticationSession.secureMessagingKeys(
            oid: SecurityInfo.ID_CA_DH_3DES_CBC_CBC_OID,
            sharedSecret: sharedSecret
        )
        XCTAssertEqual(desKeys.encryptionAlgorithm, .DES)
        XCTAssertEqual(desKeys.ksEnc, try generator.deriveKey(keySeed: sharedSecret, cipherAlgName: "DESede", keyLength: 128, mode: .ENC_MODE))
        XCTAssertEqual(desKeys.ksMac, try generator.deriveKey(keySeed: sharedSecret, cipherAlgName: "DESede", keyLength: 128, mode: .MAC_MODE))
        XCTAssertEqual(desKeys.ssc, [UInt8](repeating: 0, count: 8))
    }
}

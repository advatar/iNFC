//
//  ChipAuthenticationSession.swift
//  NFCPassportReader
//

import Foundation

@available(iOS 13, macOS 10.15, *)
struct ChipAuthenticationSecureMessagingKeys {
    let encryptionAlgorithm: SecureMessagingSupportedAlgorithms
    let ksEnc: [UInt8]
    let ksMac: [UInt8]
    let ssc: [UInt8]
}

@available(iOS 13, macOS 10.15, *)
enum ChipAuthenticationSession {
    static let commandChainingChunkSize = 224

    static func inferredAuthenticationOID(fromPublicKeyOID oid: String) -> String? {
        switch oid {
        case SecurityInfo.ID_PK_ECDH_OID:
            return SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC_OID
        case SecurityInfo.ID_PK_DH_OID:
            return SecurityInfo.ID_CA_DH_3DES_CBC_CBC_OID
        default:
            return nil
        }
    }

    static func authenticationOID(
        for publicKeyInfo: ChipAuthenticationPublicKeyInfo,
        authenticationInfosByKeyId: [Int: ChipAuthenticationInfo]
    ) -> String? {
        if let authenticationInfo = authenticationInfosByKeyId[publicKeyInfo.keyId ?? 0] {
            return authenticationInfo.oid
        }

        return inferredAuthenticationOID(fromPublicKeyOID: publicKeyInfo.oid)
    }

    static func keyAgreementTemplateData(publicKeyData: [UInt8], keyId: Int?) -> (keyData: Data, idData: Data?) {
        let keyData = Data(wrapDO(b: 0x91, arr: publicKeyData))
        guard let keyId else {
            return (keyData, nil)
        }

        let idData = Data(wrapDO(b: 0x84, arr: intToBytes(val: keyId, removePadding: true)))
        return (keyData, idData)
    }

    static func generalAuthenticateData(publicKeyData: [UInt8]) -> [UInt8] {
        wrapDO(b: 0x80, arr: publicKeyData)
    }

    static func chunks(of data: [UInt8], segmentSize: Int = commandChainingChunkSize) -> [[UInt8]] {
        precondition(segmentSize > 0, "segmentSize must be greater than zero")
        return stride(from: 0, to: data.count, by: segmentSize).map {
            Array(data[$0 ..< Swift.min($0 + segmentSize, data.count)])
        }
    }

    static func secureMessagingKeys(
        oid: String,
        sharedSecret: [UInt8]
    ) throws -> ChipAuthenticationSecureMessagingKeys {
        let cipherAlg = try ChipAuthenticationInfo.toCipherAlgorithm(oid: oid)
        let keyLength = try ChipAuthenticationInfo.toKeyLength(oid: oid)

        let smskg = SecureMessagingSessionKeyGenerator()
        let ksEnc = try smskg.deriveKey(
            keySeed: sharedSecret,
            cipherAlgName: cipherAlg,
            keyLength: keyLength,
            mode: .ENC_MODE
        )
        let ksMac = try smskg.deriveKey(
            keySeed: sharedSecret,
            cipherAlgName: cipherAlg,
            keyLength: keyLength,
            mode: .MAC_MODE
        )

        let encryptionAlgorithm: SecureMessagingSupportedAlgorithms
        if cipherAlg.hasPrefix("DESede") {
            encryptionAlgorithm = .DES
        } else if cipherAlg.hasPrefix("AES") {
            encryptionAlgorithm = .AES
        } else {
            throw NFCPassportReaderError.InvalidDataPassed("Unsupported cipher algorithm \(cipherAlg)")
        }

        return ChipAuthenticationSecureMessagingKeys(
            encryptionAlgorithm: encryptionAlgorithm,
            ksEnc: ksEnc,
            ksMac: ksMac,
            ssc: withUnsafeBytes(of: 0.bigEndian, Array.init)
        )
    }
}

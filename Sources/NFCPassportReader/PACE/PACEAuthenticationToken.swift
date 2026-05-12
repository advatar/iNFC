//
//  PACEAuthenticationToken.swift
//  NFCPassportReader
//
//  Created by OpenAI Codex on 21/04/2026.
//

import CryptoTokenKit
import Foundation

@available(iOS 13, macOS 10.15, *)
enum PACEAuthenticationToken {
    enum KeyAgreementAlgorithm {
        case dh
        case ecdh

        var publicKeyTag: TKTLVTag {
            switch self {
            case .dh:
                return 0x84
            case .ecdh:
                return 0x86
            }
        }
    }

    static func encodePublicKey(
        protocolOID: String,
        publicKeyData: [UInt8],
        keyAgreementAlgorithm: KeyAgreementAlgorithm
    ) throws -> [UInt8] {
        let encodedOID = oidToBytes(oid: protocolOID, replaceTag: false)
        guard let oidRecord = TKBERTLVRecord(from: Data(encodedOID)) else {
            throw NFCPassportReaderError.InvalidASN1Value
        }

        let publicKeyRecord = TKBERTLVRecord(
            tag: keyAgreementAlgorithm.publicKeyTag,
            value: Data(publicKeyData)
        )
        let tokenInput = TKBERTLVRecord(tag: 0x7F49, records: [oidRecord, publicKeyRecord])
        return [UInt8](tokenInput.data)
    }

    static func generate(
        protocolOID: String,
        publicKeyData: [UInt8],
        keyAgreementAlgorithm: KeyAgreementAlgorithm,
        macKey: [UInt8],
        cipherAlgorithm: String
    ) throws -> [UInt8] {
        let encodedPublicKey = try encodePublicKey(
            protocolOID: protocolOID,
            publicKeyData: publicKeyData,
            keyAgreementAlgorithm: keyAgreementAlgorithm
        )
        return try generate(
            encodedPublicKeyData: encodedPublicKey,
            macKey: macKey,
            cipherAlgorithm: cipherAlgorithm
        )
    }

    static func generate(
        encodedPublicKeyData: [UInt8],
        macKey: [UInt8],
        cipherAlgorithm: String
    ) throws -> [UInt8] {
        let normalizedCipher = cipherAlgorithm.lowercased()
        let tokenInput: [UInt8]
        let macAlgorithm: SecureMessagingSupportedAlgorithms

        if normalizedCipher == "desede" || normalizedCipher == "3des" {
            tokenInput = pad(encodedPublicKeyData, blockSize: 8)
            macAlgorithm = .DES
        } else if normalizedCipher == "aes" || normalizedCipher.hasPrefix("aes") {
            tokenInput = encodedPublicKeyData
            macAlgorithm = .AES
        } else {
            throw NFCPassportReaderError.UnsupportedCipherAlgorithm
        }

        let macValue = mac(algoName: macAlgorithm, key: macKey, msg: tokenInput)
        guard macValue.count >= 8 else {
            throw NFCPassportReaderError.InvalidDataPassed("Unable to generate PACE authentication token")
        }

        return [UInt8](macValue.prefix(8))
    }
}

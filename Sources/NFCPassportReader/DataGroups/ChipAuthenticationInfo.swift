//
//  ChipAuthenticationInfo.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 25/02/2021.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public class ChipAuthenticationInfo : SecurityInfo {
    private struct ProtocolAttributes {
        let oid: String
        let name: String
        let keyAgreementAlgorithm: String
        let cipherAlgorithm: String
        let keyLength: Int
    }

    private static let protocolAttributes: [ProtocolAttributes] = [
        ProtocolAttributes(oid: ID_CA_DH_3DES_CBC_CBC_OID, name: "id-CA-DH-3DES-CBC-CBC", keyAgreementAlgorithm: "DH", cipherAlgorithm: "DESede", keyLength: 128),
        ProtocolAttributes(oid: ID_CA_DH_AES_CBC_CMAC_128_OID, name: "id-CA-DH-AES-CBC-CMAC-128", keyAgreementAlgorithm: "DH", cipherAlgorithm: "AES", keyLength: 128),
        ProtocolAttributes(oid: ID_CA_DH_AES_CBC_CMAC_192_OID, name: "id-CA-DH-AES-CBC-CMAC-192", keyAgreementAlgorithm: "DH", cipherAlgorithm: "AES", keyLength: 192),
        ProtocolAttributes(oid: ID_CA_DH_AES_CBC_CMAC_256_OID, name: "id-CA-DH-AES-CBC-CMAC-256", keyAgreementAlgorithm: "DH", cipherAlgorithm: "AES", keyLength: 256),
        ProtocolAttributes(oid: ID_CA_ECDH_3DES_CBC_CBC_OID, name: "id-CA-ECDH-3DES-CBC-CBC", keyAgreementAlgorithm: "ECDH", cipherAlgorithm: "DESede", keyLength: 128),
        ProtocolAttributes(oid: ID_CA_ECDH_AES_CBC_CMAC_128_OID, name: "id-CA-ECDH-AES-CBC-CMAC-128", keyAgreementAlgorithm: "ECDH", cipherAlgorithm: "AES", keyLength: 128),
        ProtocolAttributes(oid: ID_CA_ECDH_AES_CBC_CMAC_192_OID, name: "id-CA-ECDH-AES-CBC-CMAC-192", keyAgreementAlgorithm: "ECDH", cipherAlgorithm: "AES", keyLength: 192),
        ProtocolAttributes(oid: ID_CA_ECDH_AES_CBC_CMAC_256_OID, name: "id-CA-ECDH-AES-CBC-CMAC-256", keyAgreementAlgorithm: "ECDH", cipherAlgorithm: "AES", keyLength: 256)
    ]
    
    var oid : String
    var version : Int
    var keyId : Int?
    
    static func checkRequiredIdentifier(_ oid : String) -> Bool {
        return protocolAttributes.contains { $0.oid == oid }
    }
    
    init(oid: String, version: Int, keyId: Int? = nil) {
        self.oid = oid
        self.version = version
        self.keyId = keyId
    }
    
    public override func getObjectIdentifier() -> String {
        return oid
    }
    
    public override func getProtocolOIDString() -> String {
        return ChipAuthenticationInfo.toProtocolOIDString(oid:oid)
    }
    
    // The keyid refers to a specific key if there are multiple otherwise if not set, only one key is present so set to 0
    public func getKeyId() -> Int {
        return keyId ?? 0
    }
    
    /// Returns the key agreement algorithm - DH or ECDH for the given Chip Authentication oid
    /// - Parameter oid: the object identifier
    /// - Returns: key agreement algorithm
    /// - Throws: InvalidDataPassed error if invalid oid specified
    public static func toKeyAgreementAlgorithm( oid : String ) throws -> String {
        return try attributes(for: oid, errorDescription: "Unable to lookup key agreement algorithm - invalid oid").keyAgreementAlgorithm
    }
    
    /// Returns the cipher algorithm - DESede or AES for the given Chip Authentication oid
    /// - Parameter oid: the object identifier
    /// - Returns: the cipher algorithm type
    /// - Throws: InvalidDataPassed error if invalid oid specified
    public static func toCipherAlgorithm( oid : String ) throws -> String {
        return try attributes(for: oid, errorDescription: "Unable to lookup cipher algorithm - invalid oid").cipherAlgorithm
    }
    
    /// Returns the key length in bits (128, 192, or 256) for the given Chip Authentication oid
    /// - Parameter oid: the object identifier
    /// - Returns: the key length in bits
    /// - Throws: InvalidDataPassed error if invalid oid specified
    public static func toKeyLength( oid : String ) throws -> Int {
        return try attributes(for: oid, errorDescription: "Unable to get key length - invalid oid").keyLength
    }
    
    private static func toProtocolOIDString(oid : String) -> String {
        return protocolAttributes.first { $0.oid == oid }?.name ?? oid
    }

    private static func attributes(for oid: String, errorDescription: String) throws -> ProtocolAttributes {
        guard let attributes = protocolAttributes.first(where: { $0.oid == oid }) else {
            throw NFCPassportReaderError.InvalidDataPassed(errorDescription)
        }
        return attributes
    }
}

//
//  PaceInfo.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 03/03/2021.
//

import Foundation
import OSLog

public enum PACEMappingType: Equatable {
    case GM  // Generic Mapping
    case IM  // Integrated Mapping
    case CAM // Chip Authentication Mapping
    
    func description () -> String {
        switch self {
            case .GM:
                return "Generic Mapping"
            case .IM:
                return "Integrated Mapping"
            case .CAM:
                return "Chip Authentication Mapping"
        }
    }
}

@available(iOS 13, macOS 10.15, *)
public class PACEInfo : SecurityInfo {
    private struct ProtocolAttributes {
        let oid: String
        let name: String
        let mappingType: PACEMappingType
        let keyAgreementAlgorithm: String
        let cipherAlgorithm: String
        let digestAlgorithm: String
        let keyLength: Int
    }
    
    // Standardized domain parameters. Based on Table 6.
    public static let PARAM_ID_GFP_1024_160 = 0
    public static let PARAM_ID_GFP_2048_224 = 1
    public static let PARAM_ID_GFP_2048_256 = 2
    public static let PARAM_ID_ECP_NIST_P192_R1 = 8
    public static let PARAM_ID_ECP_BRAINPOOL_P192_R1 = 9
    public static let PARAM_ID_ECP_NIST_P224_R1 = 10
    public static let PARAM_ID_ECP_BRAINPOOL_P224_R1 = 11
    public static let PARAM_ID_ECP_NIST_P256_R1 = 12
    public static let PARAM_ID_ECP_BRAINPOOL_P256_R1 = 13
    public static let PARAM_ID_ECP_BRAINPOOL_P320_R1 = 14
    public static let PARAM_ID_ECP_NIST_P384_R1 = 15
    public static let PARAM_ID_ECP_BRAINPOOL_P384_R1 = 16
    public static let PARAM_ID_ECP_BRAINPOOL_P512_R1 = 17
    public static let PARAM_ID_ECP_NIST_P521_R1 = 18

    private static let protocolAttributes: [ProtocolAttributes] = [
        ProtocolAttributes(oid: ID_PACE_DH_GM_3DES_CBC_CBC, name: "id-PACE-DH-GM-3DES-CBC-CBC", mappingType: .GM, keyAgreementAlgorithm: "DH", cipherAlgorithm: "DESede", digestAlgorithm: "SHA-1", keyLength: 128),
        ProtocolAttributes(oid: ID_PACE_DH_GM_AES_CBC_CMAC_128, name: "id-PACE-DH-GM-AES-CBC-CMAC-128", mappingType: .GM, keyAgreementAlgorithm: "DH", cipherAlgorithm: "AES", digestAlgorithm: "SHA-1", keyLength: 128),
        ProtocolAttributes(oid: ID_PACE_DH_GM_AES_CBC_CMAC_192, name: "id-PACE-DH-GM-AES-CBC-CMAC-192", mappingType: .GM, keyAgreementAlgorithm: "DH", cipherAlgorithm: "AES", digestAlgorithm: "SHA-256", keyLength: 192),
        ProtocolAttributes(oid: ID_PACE_DH_GM_AES_CBC_CMAC_256, name: "id-PACE-DH-GM-AES-CBC-CMAC-256", mappingType: .GM, keyAgreementAlgorithm: "DH", cipherAlgorithm: "AES", digestAlgorithm: "SHA-256", keyLength: 256),
        ProtocolAttributes(oid: ID_PACE_DH_IM_3DES_CBC_CBC, name: "id-PACE-DH-IM-3DES-CBC-CBC", mappingType: .IM, keyAgreementAlgorithm: "DH", cipherAlgorithm: "DESede", digestAlgorithm: "SHA-1", keyLength: 128),
        ProtocolAttributes(oid: ID_PACE_DH_IM_AES_CBC_CMAC_128, name: "id-PACE-DH-IM-AES-CBC-CMAC-128", mappingType: .IM, keyAgreementAlgorithm: "DH", cipherAlgorithm: "AES", digestAlgorithm: "SHA-1", keyLength: 128),
        ProtocolAttributes(oid: ID_PACE_DH_IM_AES_CBC_CMAC_192, name: "id-PACE-DH-IM-AES-CBC-CMAC-192", mappingType: .IM, keyAgreementAlgorithm: "DH", cipherAlgorithm: "AES", digestAlgorithm: "SHA-256", keyLength: 192),
        ProtocolAttributes(oid: ID_PACE_DH_IM_AES_CBC_CMAC_256, name: "id-PACE-DH-IM-AES-CBC-CMAC-256", mappingType: .IM, keyAgreementAlgorithm: "DH", cipherAlgorithm: "AES", digestAlgorithm: "SHA-256", keyLength: 256),
        ProtocolAttributes(oid: ID_PACE_ECDH_GM_3DES_CBC_CBC, name: "id-PACE-ECDH-GM-3DES-CBC-CBC", mappingType: .GM, keyAgreementAlgorithm: "ECDH", cipherAlgorithm: "DESede", digestAlgorithm: "SHA-1", keyLength: 128),
        ProtocolAttributes(oid: ID_PACE_ECDH_GM_AES_CBC_CMAC_128, name: "id-PACE-ECDH-GM-AES-CBC-CMAC-128", mappingType: .GM, keyAgreementAlgorithm: "ECDH", cipherAlgorithm: "AES", digestAlgorithm: "SHA-1", keyLength: 128),
        ProtocolAttributes(oid: ID_PACE_ECDH_GM_AES_CBC_CMAC_192, name: "id-PACE-ECDH-GM-AES-CBC-CMAC-192", mappingType: .GM, keyAgreementAlgorithm: "ECDH", cipherAlgorithm: "AES", digestAlgorithm: "SHA-256", keyLength: 192),
        ProtocolAttributes(oid: ID_PACE_ECDH_GM_AES_CBC_CMAC_256, name: "id-PACE-ECDH-GM-AES-CBC-CMAC-256", mappingType: .GM, keyAgreementAlgorithm: "ECDH", cipherAlgorithm: "AES", digestAlgorithm: "SHA-256", keyLength: 256),
        ProtocolAttributes(oid: ID_PACE_ECDH_IM_3DES_CBC_CBC, name: "id-PACE-ECDH-IM-3DES-CBC-CBC", mappingType: .IM, keyAgreementAlgorithm: "ECDH", cipherAlgorithm: "DESede", digestAlgorithm: "SHA-1", keyLength: 128),
        ProtocolAttributes(oid: ID_PACE_ECDH_IM_AES_CBC_CMAC_128, name: "id-PACE-ECDH-IM-AES-CBC-CMAC-128", mappingType: .IM, keyAgreementAlgorithm: "ECDH", cipherAlgorithm: "AES", digestAlgorithm: "SHA-1", keyLength: 128),
        ProtocolAttributes(oid: ID_PACE_ECDH_IM_AES_CBC_CMAC_192, name: "id-PACE-ECDH-IM-AES-CBC-CMAC-192", mappingType: .IM, keyAgreementAlgorithm: "ECDH", cipherAlgorithm: "AES", digestAlgorithm: "SHA-256", keyLength: 192),
        ProtocolAttributes(oid: ID_PACE_ECDH_IM_AES_CBC_CMAC_256, name: "id-PACE-ECDH-IM-AES-CBC-CMAC-256", mappingType: .IM, keyAgreementAlgorithm: "ECDH", cipherAlgorithm: "AES", digestAlgorithm: "SHA-256", keyLength: 256),
        ProtocolAttributes(oid: ID_PACE_ECDH_CAM_AES_CBC_CMAC_128, name: "id-PACE-ECDH-CAM-AES-CBC-CMAC-128", mappingType: .CAM, keyAgreementAlgorithm: "ECDH", cipherAlgorithm: "AES", digestAlgorithm: "SHA-1", keyLength: 128),
        ProtocolAttributes(oid: ID_PACE_ECDH_CAM_AES_CBC_CMAC_192, name: "id-PACE-ECDH-CAM-AES-CBC-CMAC-192", mappingType: .CAM, keyAgreementAlgorithm: "ECDH", cipherAlgorithm: "AES", digestAlgorithm: "SHA-256", keyLength: 192),
        ProtocolAttributes(oid: ID_PACE_ECDH_CAM_AES_CBC_CMAC_256, name: "id-PACE-ECDH-CAM-AES-CBC-CMAC-256", mappingType: .CAM, keyAgreementAlgorithm: "ECDH", cipherAlgorithm: "AES", digestAlgorithm: "SHA-256", keyLength: 256)
    ]

    static let allowedIdentifiers = protocolAttributes.map(\.oid)

    var oid : String
    var version : Int
    var parameterId : Int?
    
    static func checkRequiredIdentifier(_ oid : String) -> Bool {
        return allowedIdentifiers.contains( oid )
    }
    
    init(oid: String, version: Int, parameterId: Int?) {
        self.oid = oid
        self.version = version
        self.parameterId = parameterId
    }
    
    public override func getObjectIdentifier() -> String {
        return oid
    }
    
    public override func getProtocolOIDString() -> String {
        return PACEInfo.toProtocolOIDString(oid:oid)
    }
    
    public func getVersion() -> Int {
        return version
    }
    
    public func getParameterId() -> Int? {
        return parameterId
    }
    
    public func getParameterSpec() throws -> Int32 {
        return try PACEInfo.getParameterSpec(stdDomainParam: self.parameterId ?? -1 )
    }
    
    public func getMappingType() throws -> PACEMappingType {
        return try PACEInfo.toMappingType(oid: oid); // Either GM, CAM, or IM.
    }
    
    public func getKeyAgreementAlgorithm() throws -> String {
        return try PACEInfo.toKeyAgreementAlgorithm(oid: oid); // Either DH or ECDH.
    }
    
    public func getCipherAlgorithm() throws -> String {
        return try PACEInfo.toCipherAlgorithm(oid: oid); // Either DESede or AES.
    }
    
    public func getDigestAlgorithm() throws -> String {
        return try PACEInfo.toDigestAlgorithm(oid: oid); // Either SHA-1 or SHA-256.
    }
    
    public func getKeyLength() throws -> Int {
        return try PACEInfo.toKeyLength(oid: oid); // Of the enc cipher. Either 128, 192, or 256.
    }

    public static func getParameterSpec(stdDomainParam : Int) throws -> Int32 {
        switch (stdDomainParam) {
            case PARAM_ID_GFP_1024_160:
                return Int32(PARAM_ID_GFP_1024_160)
            case PARAM_ID_GFP_2048_224:
                return Int32(PARAM_ID_GFP_2048_224)
            case PARAM_ID_GFP_2048_256:
                return Int32(PARAM_ID_GFP_2048_256)
            case PARAM_ID_ECP_NIST_P192_R1:
                return Int32(PARAM_ID_ECP_NIST_P192_R1)
            case PARAM_ID_ECP_NIST_P224_R1:
                return Int32(PARAM_ID_ECP_NIST_P224_R1)
            case PARAM_ID_ECP_NIST_P256_R1:
                return Int32(PARAM_ID_ECP_NIST_P256_R1)
            case PARAM_ID_ECP_NIST_P384_R1:
                return Int32(PARAM_ID_ECP_NIST_P384_R1)
            case PARAM_ID_ECP_BRAINPOOL_P192_R1:
                return Int32(PARAM_ID_ECP_BRAINPOOL_P192_R1)
            case PARAM_ID_ECP_BRAINPOOL_P224_R1:
                return Int32(PARAM_ID_ECP_BRAINPOOL_P224_R1)
            case PARAM_ID_ECP_BRAINPOOL_P256_R1:
                return Int32(PARAM_ID_ECP_BRAINPOOL_P256_R1)
            case PARAM_ID_ECP_BRAINPOOL_P320_R1:
                return Int32(PARAM_ID_ECP_BRAINPOOL_P320_R1)
            case PARAM_ID_ECP_BRAINPOOL_P384_R1:
                return Int32(PARAM_ID_ECP_BRAINPOOL_P384_R1)
            case PARAM_ID_ECP_BRAINPOOL_P512_R1:
                return Int32(PARAM_ID_ECP_BRAINPOOL_P512_R1)
            case PARAM_ID_ECP_NIST_P521_R1:
                return Int32(PARAM_ID_ECP_NIST_P521_R1)
            default:
                throw NFCPassportReaderError.InvalidDataPassed( "Unable to lookup p arameterSpec - invalid oid" )
        }
    }
    
    public static func toMappingType( oid : String ) throws -> PACEMappingType {
        return try attributes(for: oid, errorDescription: "Unable to lookup mapping type - invalid oid").mappingType
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
    
    public static func toDigestAlgorithm( oid : String ) throws -> String {
        return try attributes(for: oid, errorDescription: "Unable to lookup digest algorithm - invalid oid").digestAlgorithm

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

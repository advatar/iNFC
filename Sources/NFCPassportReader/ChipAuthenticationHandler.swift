//
//  ChipAuthenticationHandler.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 25/02/2021.
//

import Foundation
import OSLog

#if !os(macOS)
import CoreNFC

@available(iOS 15, *)
class ChipAuthenticationHandler {
    
    private let crypto: PassportCryptoProvider
    var tagReader : TagReader?
    var gaSegments = [[UInt8]]()
    
    var chipAuthInfos = [Int:ChipAuthenticationInfo]()
    var chipAuthPublicKeyInfos = [ChipAuthenticationPublicKeyInfo]()
    
    var isChipAuthenticationSupported : Bool = false
    
    public init(
        dg14 : DataGroup14,
        tagReader: TagReader,
        crypto: PassportCryptoProvider = PassportCrypto.provider
    ) {
        self.tagReader = tagReader
        self.crypto = crypto
        
        for secInfo in dg14.securityInfos {
            if let cai = secInfo as? ChipAuthenticationInfo {
                let keyId = cai.getKeyId()
                chipAuthInfos[keyId] = cai
            } else if let capki = secInfo as? ChipAuthenticationPublicKeyInfo {
                chipAuthPublicKeyInfos.append(capki)
            }
        }
        
        if chipAuthPublicKeyInfos.count > 0 {
            isChipAuthenticationSupported = true
        }
    }

    public func doChipAuthentication() async throws  {
                
        Logger.chipAuth.info( "Performing Chip Authentication - number of public keys found - \(self.chipAuthPublicKeyInfos.count)" )
        guard isChipAuthenticationSupported else {
            throw NFCPassportReaderError.NotYetSupported( "ChipAuthentication not supported" )
        }
        
        var success = false
        for pubKey in chipAuthPublicKeyInfos {
            do {
                success = try await self.doChipAuthentication( with: pubKey)
                if success {
                    break
                }
            } catch {
                // try next key
            }
        }
        
        if !success {
            throw NFCPassportReaderError.ChipAuthenticationFailed
        }
    }
    
    private func doChipAuthentication( with chipAuthPublicKeyInfo : ChipAuthenticationPublicKeyInfo ) async throws -> Bool {
        
        guard let chipAuthInfoOID = ChipAuthenticationSession.authenticationOID(
            for: chipAuthPublicKeyInfo,
            authenticationInfosByKeyId: chipAuthInfos
        ) else {
            Logger.chipAuth.warning("No ChipAuthenticationInfo and unsupported ChipAuthenticationPublicKeyInfo public key OID \(chipAuthPublicKeyInfo.oid)")
            return false
        }
        if chipAuthInfos[chipAuthPublicKeyInfo.keyId ?? 0] == nil {
            Logger.chipAuth.warning("No ChipAuthenticationInfo - inferred \(chipAuthInfoOID) from ChipAuthenticationPublicKeyInfo")
        }

        try await self.doCA( keyId: chipAuthPublicKeyInfo.keyId, encryptionDetailsOID: chipAuthInfoOID, publicKey: chipAuthPublicKeyInfo.pubKey )
        return true
    }
    
    private func doCA( keyId: Int?, encryptionDetailsOID oid: String, publicKey: PassportPublicKey) async throws {
        let ephemeralKeyPair = try crypto.generateChipAuthenticationKeyPair(using: publicKey)
        
        // Send the public key to the passport
        try await sendPublicKey(oid: oid, keyId: keyId, pcdPublicKey: ephemeralKeyPair)
            
        Logger.chipAuth.debug( "Public Key successfully sent to passport!" )
        
        // Use our ephemeral private key and the passports public key to generate a shared secret
        // (the passport with do the same thing with their private key and our public key)
        let sharedSecret = try crypto.computeSharedSecret(
            privateKeyPair: ephemeralKeyPair,
            publicKey: publicKey
        )
        
        // Now try to restart Secure Messaging using the new shared secret and
        try restartSecureMessaging( oid : oid, sharedSecret : sharedSecret, maxTranceiveLength : 1, shouldCheckMAC : true)
    }
    
    private func sendPublicKey(oid : String, keyId : Int?, pcdPublicKey : PassportKeyPair) async throws {
        let cipherAlg = try ChipAuthenticationInfo.toCipherAlgorithm(oid: oid)
        let keyData = try crypto.encodedPublicKey(from: pcdPublicKey)
        
        if cipherAlg.hasPrefix("DESede") {
            let templateData = ChipAuthenticationSession.keyAgreementTemplateData(
                publicKeyData: keyData,
                keyId: keyId
            )
            _ = try await self.tagReader?.sendMSEKAT(
                keyData: templateData.keyData,
                idData: templateData.idData
            )
        } else if cipherAlg.hasPrefix("AES") {
            _ = try await self.tagReader?.sendMSESetATIntAuth(oid: oid, keyId: keyId)
            let data = ChipAuthenticationSession.generalAuthenticateData(publicKeyData: keyData)
            gaSegments = ChipAuthenticationSession.chunks(of: data)
            try await self.handleGeneralAuthentication()
        } else {
            throw NFCPassportReaderError.InvalidDataPassed("Cipher Algorithm \(cipherAlg) not supported")
        }
    }
    
    private func handleGeneralAuthentication() async throws {
        repeat {
            // Pull next segment from list
            let segment = gaSegments.removeFirst()
            let isLast = gaSegments.isEmpty
        
            // send it
            _ = try await self.tagReader?.sendGeneralAuthenticate(data: segment, isLast: isLast)
        } while ( !gaSegments.isEmpty )
    }
        
    private func restartSecureMessaging( oid : String, sharedSecret : [UInt8], maxTranceiveLength : Int, shouldCheckMAC : Bool) throws  {
        let secureMessagingKeys = try ChipAuthenticationSession.secureMessagingKeys(
            oid: oid,
            sharedSecret: sharedSecret
        )

        if secureMessagingKeys.encryptionAlgorithm == .DES {
            Logger.chipAuth.info( "Restarting secure messaging using DESede encryption")
            let sm = SecureMessaging(
                encryptionAlgorithm: .DES,
                ksenc: secureMessagingKeys.ksEnc,
                ksmac: secureMessagingKeys.ksMac,
                ssc: secureMessagingKeys.ssc
            )
            tagReader?.secureMessaging = sm
        } else if secureMessagingKeys.encryptionAlgorithm == .AES {
            Logger.chipAuth.info( "Restarting secure messaging using AES encryption")
            let sm = SecureMessaging(
                encryptionAlgorithm: .AES,
                ksenc: secureMessagingKeys.ksEnc,
                ksmac: secureMessagingKeys.ksMac,
                ssc: secureMessagingKeys.ssc
            )
            tagReader?.secureMessaging = sm
        }
    }
}

#endif

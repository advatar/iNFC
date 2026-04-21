//
//  TagHandler.swift
//  NFCTest
//
//  Created by Andy Qua on 09/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import Foundation
import OSLog

#if !os(macOS)
import CoreNFC

@available(iOS 15, *)
public class TagReader {
    var tag : NFCISO7816Tag
    var secureMessaging : SecureMessaging?
    var maxDataLengthToRead : Int = 0xA0  // Should be able to use 256 to read arbitrary amounts of data at full speed BUT this isn't supported across all passports so for reliability just use the smaller amount.

    var progress : ((Int)->())?

    init( tag: NFCISO7816Tag ) {
        self.tag = tag
    }
    
    func overrideDataAmountToRead( newAmount : Int ) {
        maxDataLengthToRead = newAmount
    }
    
    func reduceDataReadingAmount() {
        if maxDataLengthToRead > 0xA0 {
            maxDataLengthToRead = 0xA0
        }
    }


    func readDataGroup( dataGroup: DataGroupId ) async throws -> [UInt8]  {
        guard let tag = dataGroup.getFileIDTag() else {
            throw NFCPassportReaderError.UnsupportedDataGroup
        }
        
        return try await selectFileAndRead(tag: tag )
    }
    
    func getChallenge() async throws -> ResponseAPDU{
        try await send(cmd: APDUCommand.getChallenge)
    }
    
    func doInternalAuthentication( challenge: [UInt8], useExtendedMode: Bool ) async throws -> ResponseAPDU {
        let command = APDUCommand.internalAuthentication(challenge: challenge, useExtendedMode: useExtendedMode)
        return try await send(cmd: command, useExtendedMode: useExtendedMode)
    }

    func doMutualAuthentication( cmdData : Data ) async throws -> ResponseAPDU{
        try await send(cmd: APDUCommand.mutualAuthentication(data: cmdData))
    }
    
    /// The MSE KAT APDU, see EAC 1.11 spec, Section B.1.
    /// This command is sent in the "DESede" case.
    /// - Parameter keyData key data object (tag 0x91)
    /// - Parameter idData key id data object (tag 0x84), can be null
    /// - Parameter completed the complete handler - returns the success response or an error
    func sendMSEKAT( keyData : Data, idData: Data? ) async throws -> ResponseAPDU {
        
        try await send(cmd: APDUCommand.mseKeyAgreementTemplate(keyData: keyData, idData: idData))
    }
    
    /// The  MSE Set AT for Chip Authentication.
    /// This command is the first command that is sent in the "AES" case.
    /// For Chip Authentication. We prefix 0x80 for OID and 0x84 for keyId.
    ///
    /// NOTE THIS IS CURRENTLY UNTESTED
    /// - Parameter oid the OID
    /// - Parameter keyId the keyId or {@code null}
    /// - Parameter completed the complete handler - returns the success response or an error
    func sendMSESetATIntAuth( oid: String, keyId: Int? ) async throws -> ResponseAPDU {
        
        try await send(cmd: APDUCommand.mseSetATForInternalAuthentication(oid: oid, keyId: keyId))
    }
    
    func sendMSESetATMutualAuth( oid: String, keyType: UInt8 ) async throws -> ResponseAPDU {
        try await send(cmd: APDUCommand.mseSetATForMutualAuthentication(oid: oid, keyType: keyType))
    }
    

    /// Sends a General Authenticate command.
    /// This command is the second command that is sent in the "AES" case.
    /// - Parameter data data to be sent, without the {@code 0x7C} prefix (this method will add it)
    /// - Parameter lengthExpected the expected length defaults to 256
    /// - Parameter isLast indicates whether this is the last command in the chain
    /// - Parameter completed the complete handler - returns the dynamic authentication data without the {@code 0x7C} prefix (this method will remove it) or an error
    func sendGeneralAuthenticate( data : [UInt8], lengthExpected : Int = 256, isLast: Bool) async throws -> ResponseAPDU {

        let commandData = Data(wrapDO(b:0x7C, arr:data))
            
         // NOTE: Support of Protocol Response Data is CONDITIONAL:
         // It MUST be provided for version 2 but MUST NOT be provided for version 1.
         // So, we are expecting 0x7C (= tag), 0x00 (= length) here.
        
        var response : ResponseAPDU
        do {
            response = try await send(
                cmd: APDUCommand.generalAuthenticate(
                    wrappedData: commandData,
                    expectedResponseLength: lengthExpected,
                    isLast: isLast
                )
            )
            response.data = try unwrapDO( tag:0x7c, wrappedData:response.data)
        } catch {
            // If wrong length error
            if case NFCPassportReaderError.ResponseError(_, let sw1, let sw2) = error,
               sw1 == 0x67, sw2 == 0x00 {
                
                // Resend
                response = try await send(
                    cmd: APDUCommand.generalAuthenticate(
                        wrappedData: commandData,
                        expectedResponseLength: 256,
                        isLast: isLast
                    )
                )
                response.data = try unwrapDO( tag:0x7c, wrappedData:response.data)
            } else {
                throw error
            }
        }
        return response
    }
    

    func selectFileAndRead( tag: [UInt8]) async throws -> [UInt8] {
        var resp = try await selectFile(tag: tag )
            
        // Read first 4 bytes of header to see how big the data structure is
        resp = try await self.send(cmd: APDUCommand.readBinaryHeader())

        // Header looks like:  <tag><length of data><nextTag> e.g.60145F01 -
        // the total length is the 2nd value plus the two header 2 bytes
        // We've read 4 bytes so we now need to read the remaining bytes from offset 4
        let (len, o) = try! asn1Length([UInt8](resp.data[1..<4]))
        var remaining = Int(len)
        var amountRead = o + 1
        
        var data = [UInt8](resp.data[..<amountRead])
        
        Logger.tagReader.debug( "TagReader - Number of data bytes to read - \(remaining)" )
        
        var readAmount : Int = maxDataLengthToRead
        while remaining > 0 {
            if maxDataLengthToRead != 256 && remaining < maxDataLengthToRead {
                readAmount = remaining
            }

            self.progress?( Int(Float(amountRead) / Float(remaining+amountRead ) * 100))
            let offset = intToBin(amountRead, pad:4)

            Logger.tagReader.debug( "TagReader - data bytes remaining: \(remaining), will read : \(readAmount)" )
            resp = try await self.send(
                cmd: APDUCommand.readBinary(offset: offset, expectedResponseLength: readAmount)
            )

            Logger.tagReader.debug( "TagReader - got resp - \(binToHexRep(resp.data, asArray: true)), sw1 : \(resp.sw1), sw2 : \(resp.sw2)" )
            data += resp.data
            
            remaining -= resp.data.count
            amountRead += resp.data.count
            Logger.tagReader.debug( "TagReader - Amount of data left to read - \(remaining)" )
        }
        
        return data
    }


    func readCardAccess() async throws -> [UInt8]{
        // Info provided by @smulu
        // By default NFCISO7816Tag requirers a list of ISO/IEC 7816 applets (AIDs). Upon discovery of NFC tag the first found applet from this list is automatically selected (and you have no way of changing this).
        // This is a problem for PACE protocol becaues it requires reading parameters from file EF.CardAccess which lies outside of eMRTD applet (AID: A0000002471001) in the master file.
        
        // Now, the ICAO 9303 standard does specify command for selecting master file by sending SELECT APDU with P1=0x00, P2=0x0C and empty data field (see part 10 page 8). But after some testing I found out this command doesn't work on some passports (European passports) and although receiving success (sw=9000) from passport the master file is not selected.
        
        // After a bit of researching standard ISO/IEC 7816 I found there is an alternative SELECT command for selecting master file. The command doesn't differ much from the command specified in ICAO 9303 doc with only difference that data field is set to: 0x3F00. See section 6.11.3 of ISO/IEC 7816-4.
        // By executing above SELECT command (with data=0x3F00) master file should be selected and you should be able to read EF.CardAccess from passport.
        
        // First select master file
        _ = try await send(cmd: APDUCommand.selectMasterFile)
            
        // Now read EC.CardAccess
        let data = try await self.selectFileAndRead(tag: [0x01,0x1C])
        return data
    }
    
    func selectPassportApplication() async throws -> ResponseAPDU {
        // Finally reselect the eMRTD application so the rest of the reading works as normal
        Logger.tagReader.debug( "Re-selecting eMRTD Application" )
        let response = try await self.send(cmd: APDUCommand.selectPassportApplication)
        return response
    }
    
    func selectFile( tag: [UInt8] ) async throws -> ResponseAPDU {
        try await send(cmd: APDUCommand.selectFile(tag))
    }

    func send( cmd: NFCISO7816APDU, useExtendedMode : Bool = false ) async throws -> ResponseAPDU {
        Logger.tagReader.debug( "TagReader - sending \(cmd)" )
        var toSend = cmd
        if let sm = secureMessaging {
            toSend = try sm.protect(apdu:cmd, useExtendedMode: useExtendedMode)
            Logger.tagReader.debug("TagReader - [SM] \(toSend)" )
        }
        
        var (data, sw1, sw2) = try await tag.sendCommand(apdu: toSend)
        Logger.tagReader.debug( "TagReader - Received response, size \(data.count)b" )

        // Some commands may have bigger response than expected. Read the whole response using INS 0xC0 (GET RESPONSE).
        while sw1 == 0x61 {
            let getResponseCmd = APDUCommand.getResponse(expectedResponseLength: Int(sw2))
            let nextSegment: Data
            // Overwrite sw1 and sw2.
            (nextSegment, sw1, sw2) = try await tag.sendCommand(apdu: getResponseCmd)
            Logger.tagReader.debug("Read remaining data. Accumulated: \(data.count + nextSegment.count)b. Last batch \(nextSegment.count)b. Still remaining: \(sw2)b")
            data += nextSegment
        }

        var rep = ResponseAPDU(data: [UInt8](data), sw1: sw1, sw2: sw2)
        
        if let sm = self.secureMessaging {
            rep = try sm.unprotect(rapdu:rep)
            Logger.tagReader.debug("\(String(format:"TagReader [SM - unprotected] \(binToHexRep(rep.data, asArray:true)), sw1:0x%02x sw2:0x%02x", rep.sw1, rep.sw2))" )
        } else {
            Logger.tagReader.debug("\(String(format:"TagReader [unprotected] \(binToHexRep(rep.data, asArray:true)), sw1:0x%02x sw2:0x%02x", rep.sw1, rep.sw2))" )
            
        }
        
        if !rep.isSuccess {
            Logger.tagReader.error( "Error reading tag: sw1 - 0x\(binToHexRep(rep.sw1)), sw2 - 0x\(binToHexRep(rep.sw2))" )
            Logger.tagReader.error( "reason: \(rep.status.description)" )
            try rep.ensureSuccess()
        }

        return rep
    }
}

#endif

import Foundation
import XCTest

@testable import NFCPassportReader

@available(iOS 15, macOS 11, *)
final class PACEWorkedExampleTests: XCTestCase {
    private let dhGenericMappingAES128OID = "0.4.0.127.0.7.2.2.4.1.2"
    private let ecdhGenericMappingAES128OID = "0.4.0.127.0.7.2.2.4.2.2"

    func testMRZPACEKeyDerivationMatchesICAODoc9303AppendixG() throws {
        let generator = SecureMessagingSessionKeyGenerator()
        let mrzInformation = Array("T22000129364081251010318".utf8)

        let mrzHash = calcSHA1Hash(mrzInformation)
        XCTAssertEqual(mrzHash, bytes("7E2D2A41C74EA0B38CD36F863939BFA8E9032AAD"))

        let paceKey = try generator.deriveKey(
            keySeed: mrzHash,
            cipherAlgName: "AES",
            keyLength: 128,
            nonce: nil,
            mode: .PACE_MODE,
            paceKeyReference: 0x01
        )

        XCTAssertEqual(paceKey, bytes("89DED1B26624EC1E634C1989302849DD"))
    }

    func testECDHGenericMappingSessionKeysMatchICAODoc9303AppendixG1() throws {
        let generator = SecureMessagingSessionKeyGenerator()
        let sharedSecret = bytes("28768D20701247DAE81804C9E780EDE582A9996DB4A315020B2733197DB84925")

        let encKey = try generator.deriveKey(
            keySeed: sharedSecret,
            cipherAlgName: "AES",
            keyLength: 128,
            mode: .ENC_MODE
        )
        let macKey = try generator.deriveKey(
            keySeed: sharedSecret,
            cipherAlgName: "AES",
            keyLength: 128,
            mode: .MAC_MODE
        )

        XCTAssertEqual(encKey, bytes("F5F0E35C0D7161EE6724EE513A0D9A7F"))
        XCTAssertEqual(macKey, bytes("FE251C7858B356B24514B3BD5F4297D1"))
    }

    func testECDHGenericMappingAuthenticationTokensMatchICAODoc9303AppendixG1() throws {
        let macKey = bytes("FE251C7858B356B24514B3BD5F4297D1")
        let terminalPublicKey = bytes("""
            04
            2DB7A64C0355044EC9DF190514C625CBA2CEA48754887122F3A5EF0D5EDD301C
            3556F3B3B186DF10B857B58F6A7EB80F20BA5DC7BE1D43D9BF850149FBB36462
            """)
        let chipPublicKey = bytes("""
            04
            9E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB
            7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094
            """)

        let terminalTokenInput = try PACEAuthenticationToken.encodePublicKey(
            protocolOID: ecdhGenericMappingAES128OID,
            publicKeyData: chipPublicKey,
            keyAgreementAlgorithm: .ecdh
        )
        let chipTokenInput = try PACEAuthenticationToken.encodePublicKey(
            protocolOID: ecdhGenericMappingAES128OID,
            publicKeyData: terminalPublicKey,
            keyAgreementAlgorithm: .ecdh
        )

        XCTAssertEqual(terminalTokenInput, bytes("""
            7F494F060A04007F00070202040202864104
            9E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB
            7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094
            """))
        XCTAssertEqual(chipTokenInput, bytes("""
            7F494F060A04007F00070202040202864104
            2DB7A64C0355044EC9DF190514C625CBA2CEA48754887122F3A5EF0D5EDD301C
            3556F3B3B186DF10B857B58F6A7EB80F20BA5DC7BE1D43D9BF850149FBB36462
            """))

        let terminalToken = try PACEAuthenticationToken.generate(
            encodedPublicKeyData: terminalTokenInput,
            macKey: macKey,
            cipherAlgorithm: "AES"
        )
        let chipToken = try PACEAuthenticationToken.generate(
            encodedPublicKeyData: chipTokenInput,
            macKey: macKey,
            cipherAlgorithm: "AES"
        )

        XCTAssertEqual(terminalToken, bytes("C2B0BD78D94BA866"))
        XCTAssertEqual(chipToken, bytes("3ABB9674BCE93C08"))
        XCTAssertEqual(
            try PACEAuthenticationToken.generate(
                protocolOID: ecdhGenericMappingAES128OID,
                publicKeyData: chipPublicKey,
                keyAgreementAlgorithm: .ecdh,
                macKey: macKey,
                cipherAlgorithm: "AES"
            ),
            bytes("C2B0BD78D94BA866")
        )
    }

    func testDHGenericMappingAuthenticationTokensMatchICAODoc9303AppendixG2() throws {
        let macKey = bytes("805A1D27D45A5116F73C54469462B7D8")
        let terminalPublicKey = bytes("""
            907D89E2D425A178AA81AF4A7774EC8E388C115CAE67031E85EECE520BD911551B
            9AE4D04369F29A02626C86FBC6747CC7BC352645B6161A2A42D44EDA80A08FA8
            D61B76D3A154AD8A5A51786B0BC07147057871A922212C5F67F43173172236B7
            747D1671E6D692A3C7D40A0C3C5CE397545D015C175EB5130551EDBC2EE5D4
            """)
        let chipPublicKey = bytes("""
            075693D9AE941877573E634B6E644F8E60AF17A0076B8B123D9201074D36152B
            D8B3A213F53820C42ADC79AB5D0AEEC3AEFB91394DA476BD97B9B14D0A65C1FC
            71A0E019CB08AF55E1F729005FBA7E3FA5DC41899238A250767A6D46DB974064
            386CD456743585F8E5D90CC8B4004B1F6D866C79CE0584E49687FF61BC29AEA1
            """)

        let terminalTokenInput = try PACEAuthenticationToken.encodePublicKey(
            protocolOID: dhGenericMappingAES128OID,
            publicKeyData: chipPublicKey,
            keyAgreementAlgorithm: .dh
        )
        let chipTokenInput = try PACEAuthenticationToken.encodePublicKey(
            protocolOID: dhGenericMappingAES128OID,
            publicKeyData: terminalPublicKey,
            keyAgreementAlgorithm: .dh
        )

        XCTAssertEqual(terminalTokenInput, bytes("""
            7F49818F060A04007F00070202040102848180
            075693D9AE941877573E634B6E644F8E60AF17A0076B8B123D9201074D36152B
            D8B3A213F53820C42ADC79AB5D0AEEC3AEFB91394DA476BD97B9B14D0A65C1FC
            71A0E019CB08AF55E1F729005FBA7E3FA5DC41899238A250767A6D46DB974064
            386CD456743585F8E5D90CC8B4004B1F6D866C79CE0584E49687FF61BC29AEA1
            """))
        XCTAssertEqual(chipTokenInput, bytes("""
            7F49818F060A04007F00070202040102848180
            907D89E2D425A178AA81AF4A7774EC8E388C115CAE67031E85EECE520BD911551B
            9AE4D04369F29A02626C86FBC6747CC7BC352645B6161A2A42D44EDA80A08FA8
            D61B76D3A154AD8A5A51786B0BC07147057871A922212C5F67F43173172236B7
            747D1671E6D692A3C7D40A0C3C5CE397545D015C175EB5130551EDBC2EE5D4
            """))

        let terminalToken = try PACEAuthenticationToken.generate(
            encodedPublicKeyData: terminalTokenInput,
            macKey: macKey,
            cipherAlgorithm: "AES"
        )
        let chipToken = try PACEAuthenticationToken.generate(
            encodedPublicKeyData: chipTokenInput,
            macKey: macKey,
            cipherAlgorithm: "AES"
        )

        XCTAssertEqual(terminalToken, bytes("B46DD9BD4D98381F"))
        XCTAssertEqual(chipToken, bytes("917F37B5C0E6D8D1"))
    }

    func testGenericMappingAPDUConstructionMatchesICAODoc9303AppendixG1Transcript() {
        let setAuthenticationTemplate = APDUCommand.mseSetATForMutualAuthentication(
            oid: ecdhGenericMappingAES128OID,
            keyType: 0x01
        )
        let queryEncryptedNonce = APDUCommand.generalAuthenticate(
            wrappedData: Data(wrapDO(b: 0x7C, arr: [])),
            expectedResponseLength: 256,
            isLast: false
        )
        let sendAuthenticationToken = APDUCommand.generalAuthenticate(
            wrappedData: Data(wrapDO(b: 0x7C, arr: wrapDO(b: 0x85, arr: bytes("C2B0BD78D94BA866")))),
            expectedResponseLength: 256,
            isLast: true
        )

        XCTAssertEqual(
            shortEncodedCommand(setAuthenticationTemplate),
            bytes("0022C1A40F800A04007F00070202040202830101")
        )
        XCTAssertEqual(
            shortEncodedCommand(queryEncryptedNonce),
            bytes("10860000027C0000")
        )
        XCTAssertEqual(
            shortEncodedCommand(sendAuthenticationToken),
            bytes("008600000C7C0A8508C2B0BD78D94BA86600")
        )
    }

    private func bytes(_ hexString: String) -> [UInt8] {
        hexRepToBin(hexString.filter { !$0.isWhitespace })
    }

    private func shortEncodedCommand(_ command: APDU) -> [UInt8] {
        var encoded = [
            command.instructionClass,
            command.instructionCode,
            command.p1Parameter,
            command.p2Parameter
        ]

        if !command.data.isEmpty {
            precondition(command.data.count <= UInt8.max)
            encoded.append(UInt8(command.data.count))
            encoded.append(contentsOf: command.data)
        }

        if command.expectedResponseLength >= 0 {
            precondition(command.expectedResponseLength <= 256)
            encoded.append(command.expectedResponseLength == 256 ? 0x00 : UInt8(command.expectedResponseLength))
        }

        return encoded
    }
}

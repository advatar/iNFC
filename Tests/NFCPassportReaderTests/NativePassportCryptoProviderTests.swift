import XCTest
import Security

@testable import NFCPassportReader

@available(iOS 13, macOS 10.15, *)
final class NativePassportCryptoProviderTests: XCTestCase {
    func testDecodesRSAActiveAuthenticationPublicKeyAlgorithm() throws {
        let provider = NativePassportCryptoProvider()
        let key = try provider.decodeActiveAuthenticationPublicKey(Self.rsaSubjectPublicKeyInfo)

        XCTAssertEqual(key.algorithm, .rsa)
    }

    func testRecoversRSAActiveAuthenticationMessage() throws {
        let provider = NativePassportCryptoProvider()
        let key = try provider.decodeActiveAuthenticationPublicKey(Self.rsaSubjectPublicKeyInfo)

        // Toy RSA vector: n = 3233, e = 17, d = 2753. m = 65, signature = m^d mod n = 588.
        let recovered = try provider.recoverActiveAuthenticationMessage(
            signature: [0x02, 0x4C],
            using: key
        )

        XCTAssertEqual(recovered, [0x00, 0x41])
    }

    func testRejectsUnknownActiveAuthenticationPublicKeyAlgorithm() {
        XCTAssertThrowsError(
            try NativePassportCryptoProvider().decodeActiveAuthenticationPublicKey([0x30, 0x00])
        )
    }

    func testRejectsRSARecoveryWithNonRSAKey() {
        let provider = NativePassportCryptoProvider()
        let key = NativeActiveAuthenticationPublicKey(der: Self.ecSubjectPublicKeyInfo, algorithm: .ecdsa)

        XCTAssertThrowsError(
            try provider.recoverActiveAuthenticationMessage(signature: [0x01], using: key)
        )
    }

    func testRejectsInvalidRSASubjectPublicKeyInfoDuringRecovery() {
        let provider = NativePassportCryptoProvider()
        let key = NativeActiveAuthenticationPublicKey(der: [0x30, 0x00], algorithm: .rsa)

        XCTAssertThrowsError(
            try provider.recoverActiveAuthenticationMessage(signature: [0x01], using: key)
        )
    }

    func testChipAuthenticationGeneratesEncodesAndComputesECDHSharedSecret() throws {
        let provider = NativePassportCryptoProvider()
        let chipKeyPair = try Self.makeP256KeyPair()
        let chipPublicKey = try provider.decodeSubjectPublicKeyInfo(chipKeyPair.subjectPublicKeyInfo)
        let terminalKeyPair = try provider.generateChipAuthenticationKeyPair(using: chipPublicKey)
        let terminalPublicKeyData = try provider.encodedPublicKey(from: terminalKeyPair)

        let providerSecret = try provider.computeSharedSecret(
            privateKeyPair: terminalKeyPair,
            publicKey: chipPublicKey
        )

        let terminalPublicKey = try Self.secPublicKey(publicPoint: terminalPublicKeyData, keySizeInBits: 256)
        var error: Unmanaged<CFError>?
        guard let chipSecret = SecKeyCopyKeyExchangeResult(
            chipKeyPair.privateKey,
            .ecdhKeyExchangeStandard,
            terminalPublicKey,
            [:] as CFDictionary,
            &error
        ) as Data? else {
            throw error?.takeRetainedValue() ?? NSError(domain: "NativePassportCryptoProviderTests", code: 8)
        }

        XCTAssertEqual(providerSecret, [UInt8](chipSecret))
    }

    func testChipAuthenticationRejectsUnsupportedKeys() {
        let provider = NativePassportCryptoProvider()
        let unsupportedKeyPair = NativeUnsupportedKeyPair()

        XCTAssertThrowsError(try provider.generateChipAuthenticationKeyPair(using: NativeSecPublicKey(secKey: Self.unusableSecKey())))
        XCTAssertThrowsError(try provider.encodedPublicKey(from: unsupportedKeyPair))
        XCTAssertThrowsError(
            try provider.computeSharedSecret(
                privateKeyPair: unsupportedKeyPair,
                publicKey: NativeSubjectPublicKey(der: [])
            )
        )
    }

    func testVerifiesECDSAActiveAuthenticationDERSignature() throws {
        let provider = NativePassportCryptoProvider()
        let keyPair = try Self.makeP256KeyPair()
        let publicKey = try provider.decodeActiveAuthenticationPublicKey(keyPair.subjectPublicKeyInfo)
        let challenge = [UInt8]("passport-aa-challenge".utf8)
        let signature = try Self.sign(challenge, using: keyPair.privateKey)

        XCTAssertTrue(
            try provider.verifyActiveAuthenticationECDSASignature(
                publicKey: publicKey,
                signature: signature,
                challenge: challenge,
                digestType: "ecdsa-with-SHA256"
            )
        )
    }

    func testVerifiesECDSAActiveAuthenticationPlainSignature() throws {
        let provider = NativePassportCryptoProvider()
        let keyPair = try Self.makeP256KeyPair()
        let publicKey = try provider.decodeActiveAuthenticationPublicKey(keyPair.subjectPublicKeyInfo)
        let challenge = [UInt8]("passport-aa-challenge".utf8)
        let derSignature = try Self.sign(challenge, using: keyPair.privateKey)
        let plainSignature = try Self.plainP256Signature(fromDERSignature: derSignature)

        XCTAssertTrue(
            try provider.verifyActiveAuthenticationECDSASignature(
                publicKey: publicKey,
                signature: plainSignature,
                challenge: challenge,
                digestType: "ecdsa-with-SHA256"
            )
        )
    }

    func testRejectsECDSAActiveAuthenticationWithNonECDSAKey() throws {
        let provider = NativePassportCryptoProvider()
        let publicKey = try provider.decodeActiveAuthenticationPublicKey(Self.rsaSubjectPublicKeyInfo)

        XCTAssertThrowsError(
            try provider.verifyActiveAuthenticationECDSASignature(
                publicKey: publicKey,
                signature: [],
                challenge: [],
                digestType: ""
            )
        )
    }

    private static let rsaSubjectPublicKeyInfo = hexRepToBin("""
        301B
          300D06092A864886F70D0101010500
          030A00
            300702020CA1020111
        """.filter { !$0.isWhitespace })

    private static let ecSubjectPublicKeyInfo = hexRepToBin("""
        3013
          300906072A8648CE3D0201
          0306000401020304
        """.filter { !$0.isWhitespace })

    private struct P256KeyPair {
        let privateKey: SecKey
        let subjectPublicKeyInfo: [UInt8]
    }

    private static func makeP256KeyPair() throws -> P256KeyPair {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
              let publicKey = SecKeyCopyPublicKey(privateKey),
              let publicPoint = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw error?.takeRetainedValue() ?? NSError(domain: "NativePassportCryptoProviderTests", code: 1)
        }

        return P256KeyPair(
            privateKey: privateKey,
            subjectPublicKeyInfo: subjectPublicKeyInfo(publicPoint: [UInt8](publicPoint))
        )
    }

    private static func secPublicKey(publicPoint: [UInt8], keySizeInBits: Int) throws -> SecKey {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits: keySizeInBits
        ]

        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(Data(publicPoint) as CFData, attributes as CFDictionary, &error) else {
            throw error?.takeRetainedValue() ?? NSError(domain: "NativePassportCryptoProviderTests", code: 9)
        }
        return key
    }

    private static func unusableSecKey() -> SecKey {
        let keyPair = try! makeP256KeyPair()
        return keyPair.privateKey
    }

    private static func sign(_ message: [UInt8], using privateKey: SecKey) throws -> [UInt8] {
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            Data(message) as CFData,
            &error
        ) as Data? else {
            throw error?.takeRetainedValue() ?? NSError(domain: "NativePassportCryptoProviderTests", code: 2)
        }
        return [UInt8](signature)
    }

    private static func subjectPublicKeyInfo(publicPoint: [UInt8]) -> [UInt8] {
        let algorithmIdentifier = derSequence(
            derObjectIdentifier([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]) +
            derObjectIdentifier([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])
        )
        return derSequence(algorithmIdentifier + derBitString(publicPoint))
    }

    private static func plainP256Signature(fromDERSignature signature: [UInt8]) throws -> [UInt8] {
        var reader = TestDERReader(bytes: signature)
        var sequence = try reader.readSequence()
        let r = try sequence.readInteger()
        let s = try sequence.readInteger()
        guard reader.isAtEnd, sequence.isAtEnd else {
            throw NSError(domain: "NativePassportCryptoProviderTests", code: 3)
        }
        return leftPad(r, count: 32) + leftPad(s, count: 32)
    }

    private static func leftPad(_ bytes: [UInt8], count: Int) -> [UInt8] {
        let stripped = Array(bytes.drop { $0 == 0x00 })
        if stripped.count >= count {
            return Array(stripped.suffix(count))
        }
        return [UInt8](repeating: 0x00, count: count - stripped.count) + stripped
    }

    private static func derSequence(_ content: [UInt8]) -> [UInt8] {
        [0x30] + derLength(content.count) + content
    }

    private static func derObjectIdentifier(_ value: [UInt8]) -> [UInt8] {
        [0x06] + derLength(value.count) + value
    }

    private static func derBitString(_ value: [UInt8]) -> [UInt8] {
        [0x03] + derLength(value.count + 1) + [0x00] + value
    }

    private static func derLength(_ count: Int) -> [UInt8] {
        if count < 0x80 {
            return [UInt8(count)]
        }

        var value = count
        var bytes: [UInt8] = []
        while value > 0 {
            bytes.insert(UInt8(value & 0xFF), at: 0)
            value >>= 8
        }
        return [0x80 | UInt8(bytes.count)] + bytes
    }
}

private struct TestDERReader {
    private let bytes: [UInt8]
    private var offset: Int

    init(bytes: [UInt8]) {
        self.bytes = bytes
        self.offset = 0
    }

    var isAtEnd: Bool {
        offset == bytes.count
    }

    mutating func readSequence() throws -> TestDERReader {
        TestDERReader(bytes: try read(tag: 0x30))
    }

    mutating func readInteger() throws -> [UInt8] {
        try read(tag: 0x02)
    }

    private mutating func read(tag expectedTag: UInt8) throws -> [UInt8] {
        guard offset < bytes.count, bytes[offset] == expectedTag else {
            throw NSError(domain: "NativePassportCryptoProviderTests", code: 4)
        }
        offset += 1
        let length = try readLength()
        guard offset + length <= bytes.count else {
            throw NSError(domain: "NativePassportCryptoProviderTests", code: 5)
        }
        let content = Array(bytes[offset..<offset + length])
        offset += length
        return content
    }

    private mutating func readLength() throws -> Int {
        guard offset < bytes.count else {
            throw NSError(domain: "NativePassportCryptoProviderTests", code: 6)
        }
        let first = bytes[offset]
        offset += 1
        if first & 0x80 == 0 {
            return Int(first)
        }
        let byteCount = Int(first & 0x7F)
        guard byteCount > 0, offset + byteCount <= bytes.count else {
            throw NSError(domain: "NativePassportCryptoProviderTests", code: 7)
        }
        var length = 0
        for _ in 0..<byteCount {
            length = (length << 8) | Int(bytes[offset])
            offset += 1
        }
        return length
    }
}

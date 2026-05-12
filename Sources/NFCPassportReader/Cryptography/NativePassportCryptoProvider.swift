//
//  NativePassportCryptoProvider.swift
//  NFCPassportReader
//

import Foundation
import BigInt
import Security

@available(iOS 13, macOS 10.15, *)
final class NativeSubjectPublicKey: PassportPublicKey {
    let der: [UInt8]

    init(der: [UInt8]) {
        self.der = der
    }
}

@available(iOS 13, macOS 10.15, *)
final class NativeSecPublicKey: PassportPublicKey {
    let secKey: SecKey

    init(secKey: SecKey) {
        self.secKey = secKey
    }
}

@available(iOS 13, macOS 10.15, *)
final class NativeECKeyPair: PassportKeyPair {
    let privateKey: SecKey
    let publicKey: SecKey
    let keySizeInBits: Int

    init(privateKey: SecKey, publicKey: SecKey, keySizeInBits: Int) {
        self.privateKey = privateKey
        self.publicKey = publicKey
        self.keySizeInBits = keySizeInBits
    }
}

@available(iOS 13, macOS 10.15, *)
final class NativeUnsupportedKeyPair: PassportKeyPair {}

@available(iOS 13, macOS 10.15, *)
final class NativeActiveAuthenticationPublicKey: PassportActiveAuthenticationPublicKey {
    let der: [UInt8]
    let algorithm: PassportActiveAuthenticationKeyAlgorithm

    init(der: [UInt8], algorithm: PassportActiveAuthenticationKeyAlgorithm) {
        self.der = der
        self.algorithm = algorithm
    }
}

@available(iOS 13, macOS 10.15, *)
struct NativePassportCryptoProvider: PassportCryptoProvider {
    func decodeSubjectPublicKeyInfo(_ data: [UInt8]) throws -> PassportPublicKey {
        NativeSubjectPublicKey(der: data)
    }

    func decodeActiveAuthenticationPublicKey(_ data: [UInt8]) throws -> PassportActiveAuthenticationPublicKey {
        if containsOID(der: data, oidDERValue: Self.ecPublicKeyOIDDERValue) {
            return NativeActiveAuthenticationPublicKey(der: data, algorithm: .ecdsa)
        }
        if containsOID(der: data, oidDERValue: Self.rsaEncryptionOIDDERValue) {
            return NativeActiveAuthenticationPublicKey(der: data, algorithm: .rsa)
        }
        throw NFCPassportReaderError.NotYetSupported("Active Authentication public-key decoding for this key type")
    }

    func generateChipAuthenticationKeyPair(using publicKey: PassportPublicKey) throws -> PassportKeyPair {
        guard let publicKey = publicKey as? NativeSubjectPublicKey else {
            throw NFCPassportReaderError.InvalidDataPassed("Unsupported Chip Authentication public key")
        }

        let chipPublicKey = try ECPublicKey(derEncodedSubjectPublicKeyInfo: publicKey.der)
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: chipPublicKey.keySizeInBits
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
              let publicKey = SecKeyCopyPublicKey(privateKey) else {
            let reason = error?.takeRetainedValue().localizedDescription ?? "unknown error"
            throw NFCPassportReaderError.InvalidDataPassed("Unable to generate Chip Authentication EC keypair: \(reason)")
        }

        return NativeECKeyPair(privateKey: privateKey, publicKey: publicKey, keySizeInBits: chipPublicKey.keySizeInBits)
    }

    func encodedPublicKey(from keyPair: PassportKeyPair) throws -> [UInt8] {
        guard let keyPair = keyPair as? NativeECKeyPair else {
            throw NFCPassportReaderError.InvalidDataPassed("Unsupported Chip Authentication keypair")
        }

        var error: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(keyPair.publicKey, &error) as Data? else {
            let reason = error?.takeRetainedValue().localizedDescription ?? "unknown error"
            throw NFCPassportReaderError.InvalidDataPassed("Unable to encode Chip Authentication public key: \(reason)")
        }

        return [UInt8](publicKeyData)
    }

    func computeSharedSecret(privateKeyPair: PassportKeyPair, publicKey: PassportPublicKey) throws -> [UInt8] {
        guard let keyPair = privateKeyPair as? NativeECKeyPair,
              let publicKey = publicKey as? NativeSubjectPublicKey else {
            throw NFCPassportReaderError.InvalidDataPassed("Unsupported Chip Authentication keys")
        }

        let chipPublicKey = try ECPublicKey(derEncodedSubjectPublicKeyInfo: publicKey.der)
        guard keyPair.keySizeInBits == chipPublicKey.keySizeInBits else {
            throw NFCPassportReaderError.InvalidDataPassed("Chip Authentication key sizes do not match")
        }

        guard SecKeyIsAlgorithmSupported(keyPair.privateKey, .keyExchange, .ecdhKeyExchangeStandard) else {
            throw NFCPassportReaderError.NotYetSupported("Chip Authentication key agreement for this curve")
        }

        var error: Unmanaged<CFError>?
        guard let secret = SecKeyCopyKeyExchangeResult(
            keyPair.privateKey,
            .ecdhKeyExchangeStandard,
            chipPublicKey.secKey,
            [:] as CFDictionary,
            &error
        ) as Data? else {
            let reason = error?.takeRetainedValue().localizedDescription ?? "unknown error"
            throw NFCPassportReaderError.InvalidDataPassed("Unable to compute Chip Authentication shared secret: \(reason)")
        }

        return [UInt8](secret)
    }

    func recoverActiveAuthenticationMessage(
        signature: [UInt8],
        using publicKey: PassportActiveAuthenticationPublicKey
    ) throws -> [UInt8] {
        guard let publicKey = publicKey as? NativeActiveAuthenticationPublicKey,
              publicKey.algorithm == .rsa else {
            throw NFCPassportReaderError.InvalidDataPassed("Active Authentication key is not RSA")
        }

        let rsaPublicKey = try RSAPublicKey(derEncodedSubjectPublicKeyInfo: publicKey.der)
        let recovered = BigUInt(Data(signature)).power(rsaPublicKey.publicExponent, modulus: rsaPublicKey.modulus)
        var recoveredBytes = [UInt8](recovered.serialize())
        let keyByteCount = max(1, (rsaPublicKey.modulus.bitWidth + 7) / 8)

        if recoveredBytes.count > keyByteCount {
            recoveredBytes = [UInt8](recoveredBytes.suffix(keyByteCount))
        } else if recoveredBytes.count < keyByteCount {
            recoveredBytes = [UInt8](repeating: 0x00, count: keyByteCount - recoveredBytes.count) + recoveredBytes
        }

        return recoveredBytes
    }

    func verifyActiveAuthenticationECDSASignature(
        publicKey: PassportActiveAuthenticationPublicKey,
        signature: [UInt8],
        challenge: [UInt8],
        digestType: String
    ) throws -> Bool {
        guard let publicKey = publicKey as? NativeActiveAuthenticationPublicKey,
              publicKey.algorithm == .ecdsa else {
            throw NFCPassportReaderError.InvalidDataPassed("Active Authentication key is not ECDSA")
        }

        let ecPublicKey = try ECPublicKey(derEncodedSubjectPublicKeyInfo: publicKey.der)
        let algorithm = try Self.ecdsaVerificationAlgorithm(for: digestType)
        let derSignature = try Self.derEncodedECDSASignature(signature)

        guard SecKeyIsAlgorithmSupported(ecPublicKey.secKey, .verify, algorithm) else {
            throw NFCPassportReaderError.NotYetSupported("ECDSA Active Authentication verification for this curve or digest")
        }

        var error: Unmanaged<CFError>?
        let verified = SecKeyVerifySignature(
            ecPublicKey.secKey,
            algorithm,
            Data(challenge) as CFData,
            Data(derSignature) as CFData,
            &error
        )

        if let error {
            let retained = error.takeRetainedValue()
            throw NFCPassportReaderError.InvalidDataPassed("ECDSA signature verification failed: \(retained.localizedDescription)")
        }

        return verified
    }

    fileprivate static let rsaEncryptionOIDDERValue: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
    fileprivate static let ecPublicKeyOIDDERValue: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]

    private func containsOID(der: [UInt8], oidDERValue: [UInt8]) -> Bool {
        guard der.count >= oidDERValue.count + 2 else { return false }

        for index in 0...(der.count - oidDERValue.count - 2) {
            if der[index] == 0x06,
               der[index + 1] == UInt8(oidDERValue.count),
               Array(der[(index + 2)..<(index + 2 + oidDERValue.count)]) == oidDERValue {
                return true
            }
        }
        return false
    }

    private static func ecdsaVerificationAlgorithm(for digestType: String) throws -> SecKeyAlgorithm {
        let normalized = digestType.lowercased()

        if normalized.contains("sha1") {
            return .ecdsaSignatureMessageX962SHA1
        }
        if normalized.contains("sha224") {
            return .ecdsaSignatureMessageX962SHA224
        }
        if normalized.contains("sha256") || normalized.isEmpty {
            return .ecdsaSignatureMessageX962SHA256
        }
        if normalized.contains("sha384") {
            return .ecdsaSignatureMessageX962SHA384
        }
        if normalized.contains("sha512") {
            return .ecdsaSignatureMessageX962SHA512
        }

        throw NFCPassportReaderError.InvalidHashAlgorithmSpecified
    }

    private static func derEncodedECDSASignature(_ signature: [UInt8]) throws -> [UInt8] {
        guard !signature.isEmpty else {
            throw NFCPassportReaderError.InvalidDataPassed("Empty ECDSA signature")
        }

        if signature.first == 0x30 {
            return signature
        }

        guard signature.count.isMultiple(of: 2) else {
            throw NFCPassportReaderError.InvalidDataPassed("Invalid plain ECDSA signature length")
        }

        let componentLength = signature.count / 2
        let r = Array(signature[0..<componentLength])
        let s = Array(signature[componentLength..<signature.count])
        return DERWriter.sequence(
            DERWriter.integer(r) + DERWriter.integer(s)
        )
    }
}

@available(iOS 13, macOS 10.15, *)
private struct ECPublicKey {
    let secKey: SecKey
    let keySizeInBits: Int

    init(derEncodedSubjectPublicKeyInfo der: [UInt8]) throws {
        var spki = DERReader(bytes: der)
        var spkiSequence = try spki.readSequence()

        var algorithmIdentifier = try spkiSequence.readSequence()
        let algorithmOID = try algorithmIdentifier.readObjectIdentifierValue()
        guard algorithmOID == NativePassportCryptoProvider.ecPublicKeyOIDDERValue else {
            throw NFCPassportReaderError.InvalidDataPassed("SubjectPublicKeyInfo is not EC")
        }

        let namedCurveOID = try algorithmIdentifier.readObjectIdentifierValue()
        guard algorithmIdentifier.isAtEnd else {
            throw NFCPassportReaderError.InvalidDataPassed("Invalid EC algorithm identifier")
        }

        let publicPoint = try spkiSequence.readBitString()
        guard spkiSequence.isAtEnd, spki.isAtEnd else {
            throw NFCPassportReaderError.InvalidDataPassed("Invalid EC public key")
        }

        self.keySizeInBits = try Self.keySizeInBits(forNamedCurveOID: namedCurveOID, publicPoint: publicPoint)
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits: self.keySizeInBits
        ]

        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(Data(publicPoint) as CFData, attributes as CFDictionary, &error) else {
            let reason = error?.takeRetainedValue().localizedDescription ?? "unknown error"
            throw NFCPassportReaderError.InvalidDataPassed("Unable to import EC public key: \(reason)")
        }

        self.secKey = secKey
    }

    private static func keySizeInBits(forNamedCurveOID oid: [UInt8], publicPoint: [UInt8]) throws -> Int {
        switch oid {
        case [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]:
            return 256
        case [0x2B, 0x81, 0x04, 0x00, 0x22]:
            return 384
        case [0x2B, 0x81, 0x04, 0x00, 0x23]:
            return 521
        default:
            guard publicPoint.first == 0x04, publicPoint.count > 1, (publicPoint.count - 1).isMultiple(of: 2) else {
                throw NFCPassportReaderError.NotYetSupported("ECDSA Active Authentication named curve")
            }
            let coordinateSize = (publicPoint.count - 1) / 2
            switch coordinateSize {
            case 32: return 256
            case 48: return 384
            case 66: return 521
            default:
                throw NFCPassportReaderError.NotYetSupported("ECDSA Active Authentication named curve")
            }
        }
    }
}

@available(iOS 13, macOS 10.15, *)
private struct RSAPublicKey {
    let modulus: BigUInt
    let publicExponent: BigUInt

    init(derEncodedSubjectPublicKeyInfo der: [UInt8]) throws {
        var spki = DERReader(bytes: der)
        var spkiSequence = try spki.readSequence()

        var algorithmIdentifier = try spkiSequence.readSequence()
        let algorithmOID = try algorithmIdentifier.readObjectIdentifierValue()
        guard algorithmOID == NativePassportCryptoProvider.rsaEncryptionOIDDERValue else {
            throw NFCPassportReaderError.InvalidDataPassed("SubjectPublicKeyInfo is not RSA")
        }
        if !algorithmIdentifier.isAtEnd {
            try algorithmIdentifier.skipNull()
        }
        guard algorithmIdentifier.isAtEnd else {
            throw NFCPassportReaderError.InvalidDataPassed("Invalid RSA algorithm identifier")
        }

        var rsaKeyReader = DERReader(bytes: try spkiSequence.readBitString())
        var rsaKeySequence = try rsaKeyReader.readSequence()
        guard rsaKeyReader.isAtEnd else {
            throw NFCPassportReaderError.InvalidDataPassed("Invalid RSA public key encoding")
        }
        modulus = BigUInt(Data(try rsaKeySequence.readInteger()))
        publicExponent = BigUInt(Data(try rsaKeySequence.readInteger()))

        guard !modulus.isZero, !publicExponent.isZero, rsaKeySequence.isAtEnd, spkiSequence.isAtEnd else {
            throw NFCPassportReaderError.InvalidDataPassed("Invalid RSA public key")
        }
    }
}

@available(iOS 13, macOS 10.15, *)
private struct DERReader {
    private let bytes: [UInt8]
    private var offset: Int

    init(bytes: [UInt8]) {
        self.bytes = bytes
        self.offset = 0
    }

    var isAtEnd: Bool {
        offset == bytes.count
    }

    mutating func readSequence() throws -> DERReader {
        let content = try read(tag: 0x30)
        return DERReader(bytes: content)
    }

    mutating func readObjectIdentifierValue() throws -> [UInt8] {
        try read(tag: 0x06)
    }

    mutating func skipNull() throws {
        let content = try read(tag: 0x05)
        guard content.isEmpty else {
            throw NFCPassportReaderError.InvalidDataPassed("Invalid DER NULL")
        }
    }

    mutating func readBitString() throws -> [UInt8] {
        let content = try read(tag: 0x03)
        guard content.first == 0x00 else {
            throw NFCPassportReaderError.InvalidDataPassed("Unsupported non-octet-aligned BIT STRING")
        }
        return Array(content.dropFirst())
    }

    mutating func readInteger() throws -> [UInt8] {
        var content = try read(tag: 0x02)
        while content.count > 1, content.first == 0x00 {
            content.removeFirst()
        }
        return content
    }

    private mutating func read(tag expectedTag: UInt8) throws -> [UInt8] {
        guard offset < bytes.count, bytes[offset] == expectedTag else {
            throw NFCPassportReaderError.InvalidDataPassed("Unexpected DER tag")
        }
        offset += 1
        let length = try readLength()
        guard offset + length <= bytes.count else {
            throw NFCPassportReaderError.InvalidDataPassed("Truncated DER value")
        }
        let content = Array(bytes[offset..<offset + length])
        offset += length
        return content
    }

    private mutating func readLength() throws -> Int {
        guard offset < bytes.count else {
            throw NFCPassportReaderError.InvalidDataPassed("Missing DER length")
        }

        let first = bytes[offset]
        offset += 1

        if first & 0x80 == 0 {
            return Int(first)
        }

        let lengthByteCount = Int(first & 0x7F)
        guard lengthByteCount > 0, lengthByteCount <= MemoryLayout<Int>.size, offset + lengthByteCount <= bytes.count else {
            throw NFCPassportReaderError.InvalidDataPassed("Invalid DER length")
        }

        var length = 0
        for _ in 0..<lengthByteCount {
            length = (length << 8) | Int(bytes[offset])
            offset += 1
        }
        return length
    }
}

@available(iOS 13, macOS 10.15, *)
private enum DERWriter {
    static func sequence(_ content: [UInt8]) -> [UInt8] {
        [0x30] + length(content.count) + content
    }

    static func integer(_ value: [UInt8]) -> [UInt8] {
        var normalized = value
        while normalized.count > 1, normalized.first == 0x00, (normalized[1] & 0x80) == 0 {
            normalized.removeFirst()
        }
        if normalized.isEmpty {
            normalized = [0x00]
        }
        if normalized[0] & 0x80 != 0 {
            normalized.insert(0x00, at: 0)
        }
        return [0x02] + length(normalized.count) + normalized
    }

    private static func length(_ count: Int) -> [UInt8] {
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

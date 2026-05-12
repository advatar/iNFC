//
//  PassportCryptoProvider.swift
//  NFCPassportReader
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public protocol PassportPublicKey: AnyObject {}

@available(iOS 13, macOS 10.15, *)
public protocol PassportKeyPair: AnyObject {}

@available(iOS 13, macOS 10.15, *)
public enum PassportActiveAuthenticationKeyAlgorithm {
    case rsa
    case ecdsa
}

@available(iOS 13, macOS 10.15, *)
public protocol PassportActiveAuthenticationPublicKey: AnyObject {
    var algorithm: PassportActiveAuthenticationKeyAlgorithm { get }
}

@available(iOS 13, macOS 10.15, *)
protocol PassportCryptoProvider {
    func decodeSubjectPublicKeyInfo(_ data: [UInt8]) throws -> PassportPublicKey
    func decodeActiveAuthenticationPublicKey(_ data: [UInt8]) throws -> PassportActiveAuthenticationPublicKey
    func generateChipAuthenticationKeyPair(using publicKey: PassportPublicKey) throws -> PassportKeyPair
    func encodedPublicKey(from keyPair: PassportKeyPair) throws -> [UInt8]
    func computeSharedSecret(privateKeyPair: PassportKeyPair, publicKey: PassportPublicKey) throws -> [UInt8]
    func recoverActiveAuthenticationMessage(
        signature: [UInt8],
        using publicKey: PassportActiveAuthenticationPublicKey
    ) throws -> [UInt8]
    func verifyActiveAuthenticationECDSASignature(
        publicKey: PassportActiveAuthenticationPublicKey,
        signature: [UInt8],
        challenge: [UInt8],
        digestType: String
    ) throws -> Bool
}

@available(iOS 13, macOS 10.15, *)
enum PassportCrypto {
    static var provider: PassportCryptoProvider = NativePassportCryptoProvider()
}

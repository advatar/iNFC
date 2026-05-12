//
//  AESCMAC.swift
//  NFCPassportReader
//
//  Created by OpenAI Codex on 21/04/2026.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
enum AESCMAC {
    enum Error: Swift.Error {
        case invalidKeyLength(Int)
        case encryptionFailed
    }

    private static let blockSize = 16
    private static let rb: UInt8 = 0x87

    static func authenticate(message: [UInt8], key: [UInt8]) throws -> [UInt8] {
        guard [16, 24, 32].contains(key.count) else {
            throw Error.invalidKeyLength(key.count)
        }

        let (subkey1, subkey2) = try generateSubkeys(key: key)
        let blockCount = max(1, Int(ceil(Double(message.count) / Double(blockSize))))
        let hasCompleteFinalBlock = !message.isEmpty && message.count.isMultiple(of: blockSize)

        let finalBlock: [UInt8]
        if hasCompleteFinalBlock {
            let block = Array(message[(blockCount - 1) * blockSize..<blockCount * blockSize])
            finalBlock = xor(block, subkey1)
        } else {
            let start = (blockCount - 1) * blockSize
            let partial = start < message.count ? Array(message[start..<message.count]) : []
            finalBlock = xor(paddedBlock(partial), subkey2)
        }

        var chainingValue = [UInt8](repeating: 0x00, count: blockSize)

        if blockCount > 1 {
            for blockIndex in 0..<(blockCount - 1) {
                let block = Array(message[blockIndex * blockSize..<(blockIndex + 1) * blockSize])
                chainingValue = try encryptBlock(xor(chainingValue, block), key: key)
            }
        }

        return try encryptBlock(xor(chainingValue, finalBlock), key: key)
    }

    private static func generateSubkeys(key: [UInt8]) throws -> ([UInt8], [UInt8]) {
        let zeroBlock = [UInt8](repeating: 0x00, count: blockSize)
        let encryptedZeroBlock = try encryptBlock(zeroBlock, key: key)
        let subkey1 = doubled(encryptedZeroBlock)
        let subkey2 = doubled(subkey1)
        return (subkey1, subkey2)
    }

    private static func encryptBlock(_ block: [UInt8], key: [UInt8]) throws -> [UInt8] {
        let encrypted = AESECBEncrypt(key: key, message: block)
        guard encrypted.count == blockSize else {
            throw Error.encryptionFailed
        }
        return encrypted
    }

    private static func paddedBlock(_ block: [UInt8]) -> [UInt8] {
        var padded = block
        padded.append(0x80)
        while padded.count < blockSize {
            padded.append(0x00)
        }
        return padded
    }

    private static func doubled(_ block: [UInt8]) -> [UInt8] {
        let mostSignificantBitWasSet = block[0] & 0x80 != 0
        var doubled = leftShiftOneBit(block)
        if mostSignificantBitWasSet {
            doubled[blockSize - 1] ^= rb
        }
        return doubled
    }

    private static func leftShiftOneBit(_ block: [UInt8]) -> [UInt8] {
        var shifted = [UInt8](repeating: 0x00, count: block.count)
        var carry: UInt8 = 0

        for index in stride(from: block.count - 1, through: 0, by: -1) {
            let byte = block[index]
            shifted[index] = (byte << 1) | carry
            carry = (byte & 0x80) == 0 ? 0 : 1
        }

        return shifted
    }
}

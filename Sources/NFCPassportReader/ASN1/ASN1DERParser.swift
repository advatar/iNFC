//
//  ASN1DERParser.swift
//  NFCPassportReader
//
//  Created by OpenAI Codex on 21/04/2026.
//

import Foundation
import SwiftASN1

@available(iOS 13, macOS 10.15, *)
enum ASN1DERParser {
    static func parse(data: Data) throws -> ASN1Item {
        try item(from: DER.parse([UInt8](data)), depth: 0)
    }

    static func dump(data: Data) throws -> String {
        try dump(node: DER.parse([UInt8](data)), depth: 0).joined(separator: "\n")
    }

    static func encodeObjectIdentifier(_ oid: String) throws -> [UInt8] {
        let objectIdentifier = try ASN1ObjectIdentifier(dotRepresentation: oid)
        var serializer = DER.Serializer()
        try serializer.serialize(objectIdentifier)
        return serializer.serializedBytes
    }
}

@available(iOS 13, macOS 10.15, *)
private extension ASN1DERParser {
    struct NodeMetadata {
        let position: Int
        let headerLength: Int
        let contentLength: Int
    }

    static func item(from node: ASN1Node, depth: Int) throws -> ASN1Item {
        let metadata = try metadata(for: node)
        let isConstructed: Bool
        if case .constructed = node.content {
            isConstructed = true
        } else {
            isConstructed = false
        }

        let asn1Item = ASN1Item(
            pos: metadata.position,
            depth: depth,
            headerLen: metadata.headerLength,
            length: metadata.contentLength,
            itemType: isConstructed ? "cons" : "prim",
            type: typeDescription(for: node),
            value: valueDescription(for: node)
        )

        if case .constructed(let children) = node.content {
            for child in children {
                try asn1Item.addChild(item(from: child, depth: depth + 1))
            }
        }

        return asn1Item
    }

    static func dump(node: ASN1Node, depth: Int) throws -> [String] {
        let metadata = try metadata(for: node)
        let isConstructed: Bool
        if case .constructed = node.content {
            isConstructed = true
        } else {
            isConstructed = false
        }

        let type = typeDescription(for: node)
        let value = dumpValueDescription(for: node)
        let line = "\(metadata.position):d=\(depth) hl=\(metadata.headerLength) l=\(metadata.contentLength) \(isConstructed ? "cons" : "prim"): \(type)\(value)"

        guard case .constructed(let children) = node.content else {
            return [line]
        }

        return try children.reduce(into: [line]) { lines, child in
            try lines.append(contentsOf: dump(node: child, depth: depth + 1))
        }
    }

    static func metadata(for node: ASN1Node) throws -> NodeMetadata {
        let encodedBytes = node.encodedBytes
        let headerLength = try parseHeaderLength(encodedBytes)
        let contentLength = encodedBytes.count - headerLength
        return NodeMetadata(
            position: encodedBytes.startIndex,
            headerLength: headerLength,
            contentLength: contentLength
        )
    }

    static func parseHeaderLength(_ encodedBytes: ArraySlice<UInt8>) throws -> Int {
        guard !encodedBytes.isEmpty else {
            throw OpenSSLError.UnableToParseASN1("Empty ASN.1 node")
        }

        var index = encodedBytes.startIndex
        let firstIdentifierByte = encodedBytes[index]
        encodedBytes.formIndex(after: &index)

        if firstIdentifierByte & 0x1F == 0x1F {
            var foundFinalTagByte = false
            while index < encodedBytes.endIndex {
                let tagByte = encodedBytes[index]
                encodedBytes.formIndex(after: &index)
                if tagByte & 0x80 == 0 {
                    foundFinalTagByte = true
                    break
                }
            }

            guard foundFinalTagByte else {
                throw OpenSSLError.UnableToParseASN1("Invalid ASN.1 high-tag-number encoding")
            }
        }

        guard index < encodedBytes.endIndex else {
            throw OpenSSLError.UnableToParseASN1("Missing ASN.1 length")
        }

        let lengthByte = encodedBytes[index]
        encodedBytes.formIndex(after: &index)

        if lengthByte & 0x80 != 0 {
            let lengthByteCount = Int(lengthByte & 0x7F)
            guard lengthByteCount > 0 else {
                throw OpenSSLError.UnableToParseASN1("Indefinite ASN.1 lengths are not valid DER")
            }
            guard encodedBytes.distance(from: index, to: encodedBytes.endIndex) >= lengthByteCount else {
                throw OpenSSLError.UnableToParseASN1("Truncated ASN.1 length")
            }
            encodedBytes.formIndex(&index, offsetBy: lengthByteCount)
        }

        return encodedBytes.distance(from: encodedBytes.startIndex, to: index)
    }

    static func typeDescription(for node: ASN1Node) -> String {
        switch node.identifier.tagClass {
        case .universal:
            return universalTypeDescription(for: node.identifier.tagNumber)
        case .application:
            return "appl [ \(node.identifier.tagNumber) ]"
        case .contextSpecific:
            return "cont [ \(node.identifier.tagNumber) ]"
        case .private:
            return "priv [ \(node.identifier.tagNumber) ]"
        }
    }

    static func universalTypeDescription(for tagNumber: UInt) -> String {
        switch tagNumber {
        case ASN1Identifier.boolean.tagNumber: return "BOOLEAN"
        case ASN1Identifier.integer.tagNumber: return "INTEGER"
        case ASN1Identifier.bitString.tagNumber: return "BIT STRING"
        case ASN1Identifier.octetString.tagNumber: return "OCTET STRING"
        case ASN1Identifier.null.tagNumber: return "NULL"
        case ASN1Identifier.objectIdentifier.tagNumber: return "OBJECT"
        case 0x0C: return "UTF8STRING"
        case ASN1Identifier.sequence.tagNumber: return "SEQUENCE"
        case ASN1Identifier.set.tagNumber: return "SET"
        case 0x13: return "PRINTABLESTRING"
        case 0x16: return "IA5STRING"
        case 0x17: return "UTCTIME"
        case 0x18: return "GENERALIZEDTIME"
        default: return "UNIVERSAL \(tagNumber)"
        }
    }

    static func valueDescription(for node: ASN1Node) -> String {
        guard case .primitive(let content) = node.content else {
            return ""
        }

        switch node.identifier {
        case .objectIdentifier:
            return objectIdentifierDescription(for: node)
        case .integer, .octetString, .bitString:
            return binToHexRep([UInt8](content))
        case .utf8String, .printableString, .ia5String:
            return String(decoding: content, as: UTF8.self)
        case .null:
            return ""
        default:
            return binToHexRep([UInt8](content))
        }
    }

    static func dumpValueDescription(for node: ASN1Node) -> String {
        guard case .primitive = node.content else {
            return ""
        }

        let value = valueDescription(for: node)
        guard !value.isEmpty else {
            return ""
        }

        if node.identifier == .octetString || node.identifier == .bitString {
            return " [HEX DUMP]:\(value)"
        }

        return ":\(value)"
    }

    static func objectIdentifierDescription(for node: ASN1Node) -> String {
        guard let oid = try? ASN1ObjectIdentifier(derEncoded: node) else {
            return ""
        }

        let dotted = String(describing: oid)
        return oidNameByDottedValue[dotted] ?? dotted
    }

    static let oidNameByDottedValue: [String: String] = [
        "1.2.840.113549.1.7.1": "pkcs7-data",
        "1.2.840.113549.1.7.2": "pkcs7-signedData",
        "1.3.14.3.2.26": "sha1",
        "2.16.840.1.101.3.4.2.4": "sha224",
        "2.16.840.1.101.3.4.2.1": "sha256",
        "2.16.840.1.101.3.4.2.2": "sha384",
        "2.16.840.1.101.3.4.2.3": "sha512",
        "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
        "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
        "1.2.840.113549.1.1.10": "rsassaPss",
        "1.2.840.10045.4.1": "ecdsa-with-SHA1",
        "1.2.840.10045.4.3.1": "ecdsa-with-SHA224",
        "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4": "ecdsa-with-SHA512"
    ]
}

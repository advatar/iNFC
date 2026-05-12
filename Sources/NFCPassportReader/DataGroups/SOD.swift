//
//  SOD.swift
//
//  Created by Andy Qua on 01/02/2021.
//

import Foundation
import Security


// Format of SOD: ASN1 - Signed Data  (taken from rfc5652 - https://tools.ietf.org/html/rfc5652):
// The SOD is a CMS container of type Signed-data
//
// Note - ideally I'd be using a proper ASN1 parser, however currently there isn't a reliable one for Swift
// and I haven't written on (yet?).  So for the moment, I'm relying on the output from ASN1Dump and a
// simple parser for that
//
// Sequence
//   Object ID: signedData
//   Content: SignedData
//       SignedData ::= SEQUENCE {
//           INTEGER version CMSVersion,
//           SET digestAlgorithms DigestAlgorithmIdentifiers,
//           SEQUENCE encapContentInfo EncapsulatedContentInfo,
//           certificates [0] IMPLICIT CertificateSet OPTIONAL,
//           crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
//           SET signerInfos SignerInfos }
//
// AlgorithmIdentifier ::= SEQUENCE {
//     algorithm       OBJECT IDENTIFIER,
//     parameters      ANY OPTIONAL
// }
//
// EncapsulatedContentInfo ::= SEQUENCE {
//    eContentType ContentType,
//    eContent [0] EXPLICIT OCTET STRING OPTIONAL }
//
// ContentType ::= OBJECT IDENTIFIER
//
// SignerInfos ::= SET OF SignerInfo
//
// SignerInfo ::= SEQUENCE {
//     version CMSVersion,
//     sid SignerIdentifier,
//     digestAlgorithm DigestAlgorithmIdentifier,
//     signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
//     signatureAlgorithm SignatureAlgorithmIdentifier,
//     signature SignatureValue,
//     unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
//
// SignerIdentifier ::= CHOICE {
//     issuerAndSerialNumber IssuerAndSerialNumber,
//     subjectKeyIdentifier [0] SubjectKeyIdentifier }
//
// SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
// UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
// Attribute ::= SEQUENCE {
//     attrType OBJECT IDENTIFIER,
//     attrValues SET OF AttributeValue }
// AttributeValue ::= ANY
// SignatureValue ::= OCTET STRING
@available(iOS 13, macOS 10.15, *)
class SOD : DataGroup {
    
    public private(set) var pkcs7CertificateData : [UInt8] = []
    private var asn1 : ASN1Item!

    override var datagroupType: DataGroupId { .SOD }
    
    required init( _ data : [UInt8] ) throws {
        try super.init(data)
        self.pkcs7CertificateData = body
    }
    
    override func parse(_ data: [UInt8]) throws {
        let p = SimpleASN1DumpParser()
        asn1 = try p.parse(data: Data(body))
    }
    
    /// Returns the public key from the embedded X509 certificate
    /// - Returns provider-owned public key material.
    func getPublicKey() throws -> PassportPublicKey {
        guard let certificate = try getX509Certificates().first?.certificate,
              let publicKey = SecCertificateCopyKey(certificate) else {
            throw OpenSSLError.UnableToGetX509CertificateFromPKCS7("Unable to extract public key from SOD certificate")
        }

        return NativeSecPublicKey(secKey: publicKey)
    }

    func getX509Certificates() throws -> [X509Wrapper] {
        try CMSCertificateExtractor.certificates(fromPKCS7DER: body)
    }
    
    
    /// Extracts the encapsulated content section from a SignedData PKCS7 container (if present)
    /// - Returns: The encapsulated content from a PKCS7 container if we could read it
    /// - Throws: Error if we can't find or read the encapsulated content
    func getEncapsulatedContent() throws -> Data {
        guard let signedData = asn1.getChild(1)?.getChild(0),
              let encContent = signedData.getChild(2)?.getChild(1),
              let content = encContent.getChild(0) else {
            
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        
        var sigData : Data?
        if content.type.hasPrefix("OCTET STRING" ) {
            sigData = Data(hexRepToBin( content.value ))
        }
        
        guard let ret = sigData else { throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("noDataReturned") }
        return ret
    }
    
    /// Gets the digest algorithm used to hash the encapsulated content in the signed data section (if present)
    /// - Returns: The digest algorithm used to hash the encapsulated content in the signed data section
    /// - Throws: Error if we can't find or read the digest algorithm
    func getEncapsulatedContentDigestAlgorithm() throws -> String {
        guard let signedData = asn1.getChild(1)?.getChild(0),
              let digestAlgo = signedData.getChild(1)?.getChild(0)?.getChild(0) else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        
        return String(digestAlgo.value)
    }
    
    /// Gets the signed attributes section (if present)
    /// - Returns: the signed attributes section
    /// - Throws: Error if we can't find or read the signed attributes
    func getSignedAttributes( ) throws -> Data {
        
        // Get the SignedAttributes section.
        guard let signedData = asn1.getChild(1)?.getChild(0),
              let signerInfo = signedData.getChild(4),
              let signedAttrs = signerInfo.getChild(0)?.getChild(3) else {
            
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        
        var bytes = [UInt8](self.pkcs7CertificateData[signedAttrs.pos ..< signedAttrs.pos + signedAttrs.headerLen + signedAttrs.length])
        
        // The first byte will be 0xA0 -> as its a explicit tag for a contextual item which we need to convert
        // for the hash to calculate correctly
        // We know that the actual tag is a SET (0x31) - See section 5.4 of https://tools.ietf.org/html/rfc5652
        // So we need to change this from 0xA0 to 0x31
        if bytes[0] == 0xA0 {
            bytes[0] = 0x31
        }
        let signedAttribs = Data(bytes)
        
        return signedAttribs
    }
    
/// Gets the message digest from the signed attributes section (if present)
/// - Returns: the message digest
/// - Throws: Error if we can't find or read the message digest
    func getMessageDigestFromSignedAttributes( ) throws -> Data {
        
        // For the SOD, the SignedAttributes consists of:
        // A Content type Object (which has the value of the attributes content type)
        // A messageDigest Object which has the message digest as it value
        // We want the messageDigest value
        
        guard let signedData = asn1.getChild(1)?.getChild(0),
              let signerInfo = signedData.getChild(4),
              let signedAttrs = signerInfo.getChild(0)?.getChild(3) else {
            
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        
        // Find the messageDigest in the signedAttributes section
        var sigData : Data?
        for i in 0 ..< signedAttrs.getNumberOfChildren() {
            let attrObj = signedAttrs.getChild(i)
            if attrObj?.getChild(0)?.value == "messageDigest" {
                if let set = attrObj?.getChild(1),
                   let digestVal = set.getChild(0) {
                    
                    if digestVal.type.hasPrefix("OCTET STRING" ) {
                        sigData = Data(hexRepToBin( digestVal.value ) )
                    }
                }
            }
        }
        
        guard let messageDigest = sigData else { throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("No messageDigest Returned") }
        
        return messageDigest
    }
    
    /// Gets the signature data (if present)
    /// - Returns: the signature
    /// - Throws: Error if we can't find or read the signature
    func getSignature( ) throws -> Data {
        
        guard let signedData = asn1.getChild(1)?.getChild(0),
              let signerInfo = signedData.getChild(4),
              let signature = signerInfo.getChild(0)?.getChild(5) else {
            
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        
        var sigData : Data?
        if signature.type.hasPrefix("OCTET STRING" ) {
            sigData = Data(hexRepToBin( signature.value ))
        }
        
        guard let ret = sigData else { throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("noDataReturned") }
        return ret
    }
    
    /// Gets the signature algorithm used (if present)
    /// - Returns: the signature algorithm used
    /// - Throws: Error if we can't find or read the signature algorithm
    func getSignatureAlgorithm( ) throws -> String {
        
        guard let signedData = asn1.getChild(1)?.getChild(0),
              let signerInfo = signedData.getChild(4),
              let signatureAlgo = signerInfo.getChild(0)?.getChild(4)?.getChild(0) else {
            
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        
        // Vals I've seen are:
        // sha1WithRSAEncryption => default pkcs1
        // sha256WithRSAEncryption => default pkcs1
        // rsassaPss => pss        
        return signatureAlgo.value
    }
}

@available(iOS 13, macOS 10.15, *)
private enum CMSCertificateExtractor {
    static func certificates(fromPKCS7DER data: [UInt8]) throws -> [X509Wrapper] {
        var reader = CMSDERReader(bytes: data)
        var contentInfo = try reader.readSequence()
        _ = try contentInfo.readObjectIdentifierValue()
        var explicitSignedData = try contentInfo.readConstructed(tag: 0xA0)
        var signedData = try explicitSignedData.readSequence()

        _ = try signedData.readAny()
        _ = try signedData.readAny()
        _ = try signedData.readAny()

        guard signedData.peekTag() == 0xA0 else {
            return []
        }

        let certificatesContent = try signedData.readConstructed(tag: 0xA0).remainingBytes()
        var certificatesReader = CMSDERReader(bytes: certificatesContent)
        var certificates: [X509Wrapper] = []

        while !certificatesReader.isAtEnd {
            let certificateDER = try certificatesReader.readEncodedValue(tag: 0x30)
            if let certificate = X509Wrapper(der: certificateDER) {
                certificates.append(certificate)
            }
        }

        return certificates
    }
}

@available(iOS 13, macOS 10.15, *)
private struct CMSDERReader {
    private let bytes: [UInt8]
    private var offset: Int

    init(bytes: [UInt8]) {
        self.bytes = bytes
        self.offset = 0
    }

    var isAtEnd: Bool {
        offset == bytes.count
    }

    func remainingBytes() -> [UInt8] {
        Array(bytes[offset..<bytes.count])
    }

    func peekTag() -> UInt8? {
        guard offset < bytes.count else { return nil }
        return bytes[offset]
    }

    mutating func readSequence() throws -> CMSDERReader {
        CMSDERReader(bytes: try readValue(tag: 0x30).content)
    }

    mutating func readConstructed(tag: UInt8) throws -> CMSDERReader {
        CMSDERReader(bytes: try readValue(tag: tag).content)
    }

    mutating func readObjectIdentifierValue() throws -> [UInt8] {
        try readValue(tag: 0x06).content
    }

    mutating func readAny() throws -> [UInt8] {
        try readValue(expectedTag: nil).encoded
    }

    mutating func readEncodedValue(tag: UInt8) throws -> [UInt8] {
        try readValue(tag: tag).encoded
    }

    private mutating func readValue(tag expectedTag: UInt8) throws -> (encoded: [UInt8], content: [UInt8]) {
        try readValue(expectedTag: expectedTag)
    }

    private mutating func readValue(expectedTag: UInt8?) throws -> (encoded: [UInt8], content: [UInt8]) {
        let start = offset
        guard offset < bytes.count else {
            throw OpenSSLError.UnableToParseASN1("Missing DER tag")
        }
        let tag = bytes[offset]
        if let expectedTag, tag != expectedTag {
            throw OpenSSLError.UnableToParseASN1("Unexpected DER tag")
        }
        offset += 1
        let length = try readLength()
        let contentStart = offset
        guard offset + length <= bytes.count else {
            throw OpenSSLError.UnableToParseASN1("Truncated DER value")
        }
        offset += length
        return (
            Array(bytes[start..<offset]),
            Array(bytes[contentStart..<contentStart + length])
        )
    }

    private mutating func readLength() throws -> Int {
        guard offset < bytes.count else {
            throw OpenSSLError.UnableToParseASN1("Missing DER length")
        }

        let first = bytes[offset]
        offset += 1
        if first & 0x80 == 0 {
            return Int(first)
        }

        let lengthByteCount = Int(first & 0x7F)
        guard lengthByteCount > 0, offset + lengthByteCount <= bytes.count else {
            throw OpenSSLError.UnableToParseASN1("Invalid DER length")
        }

        var length = 0
        for _ in 0..<lengthByteCount {
            length = (length << 8) | Int(bytes[offset])
            offset += 1
        }
        return length
    }
}

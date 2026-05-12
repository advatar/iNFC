//
//  X509Wrapper.swift
//  NFCPassportReader
//

import Foundation
import Security

@available(iOS 13, macOS 10.15, *)
public enum CertificateType {
    case documentSigningCertificate
    case issuerSigningCertificate
}

@available(iOS 13, macOS 10.15, *)
public enum CertificateItem: String {
    case fingerprint = "Certificate fingerprint"
    case issuerName = "Issuer"
    case subjectName = "Subject"
    case serialNumber = "Serial number"
    case signatureAlgorithm = "Signature algorithm"
    case publicKeyAlgorithm = "Public key algorithm"
    case notBefore = "Valid from"
    case notAfter = "Valid to"
}

@available(iOS 13, macOS 10.15, *)
public class X509Wrapper {
    public let der: [UInt8]
    let certificate: SecCertificate

    public init?(der: [UInt8]) {
        guard let certificate = SecCertificateCreateWithData(nil, Data(der) as CFData) else {
            return nil
        }
        self.der = der
        self.certificate = certificate
    }

    init(certificate: SecCertificate) {
        self.certificate = certificate
        self.der = [UInt8](SecCertificateCopyData(certificate) as Data)
    }

    public func getItemsAsDict() -> [CertificateItem: String] {
        var items: [CertificateItem: String] = [:]
        items[.subjectName] = SecCertificateCopySubjectSummary(certificate) as String?
        items[.fingerprint] = (try? binToHexRep(calcHash(data: der, hashAlgorithm: "SHA256")))
        return items
    }

    public func certToPEM() -> String {
        let base64 = Data(der).base64EncodedString(options: [.lineLength64Characters])
        return "-----BEGIN CERTIFICATE-----\n\(base64)\n-----END CERTIFICATE-----\n"
    }

    static func certificates(fromPEMFile url: URL) throws -> [X509Wrapper] {
        let pem = try String(contentsOf: url, encoding: .utf8)
        let pattern = #"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\r\n]+)\s*-----END CERTIFICATE-----"#
        let regex = try NSRegularExpression(pattern: pattern)
        let nsRange = NSRange(pem.startIndex..<pem.endIndex, in: pem)

        return regex.matches(in: pem, range: nsRange).compactMap { match in
            guard let range = Range(match.range(at: 1), in: pem) else {
                return nil
            }
            let base64 = pem[range].filter { !$0.isWhitespace }
            guard let data = Data(base64Encoded: String(base64)) else {
                return nil
            }
            return X509Wrapper(der: [UInt8](data))
        }
    }
}

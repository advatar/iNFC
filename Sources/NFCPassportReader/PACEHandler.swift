//
//  PACEHandler.swift
//  NFCPassportReader
//

import Foundation

#if !os(macOS)
import CoreNFC

@available(iOS 15, *)
public class PACEHandler {
    var tagReader: TagReader
    var paceInfo: PACEInfo

    var isPACESupported: Bool = false
    var paceError: String = ""

    public init(cardAccess: CardAccess, tagReader: TagReader) throws {
        self.tagReader = tagReader

        guard let paceInfo = cardAccess.paceInfo else {
            throw NFCPassportReaderError.NotYetSupported("PACE not supported")
        }

        self.paceInfo = paceInfo
        self.isPACESupported = true
    }

    public func doPACE(mrzKey: String) async throws {
        paceError = "PACE key agreement requires the native PACE implementation"
        throw NFCPassportReaderError.NotYetSupported(paceError)
    }
}

#endif

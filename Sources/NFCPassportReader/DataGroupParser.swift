//
//  DataGroupParser.swift
//
//  Created by Andy Qua on 14/06/2019.
//

import OpenSSL

@available(iOS 13, macOS 10.15, *)
class DataGroupParser {
    
    static let dataGroupNames = DataGroupId.allCases
        .filter { $0 != .Unknown }
        .map(\.legacyParserName)

    static let tags = DataGroupId.allCases
        .filter { $0 != .Unknown }
        .map { UInt8($0.rawValue) }

    private static let dataGroupTypes: [DataGroupId: DataGroup.Type] = [
        .COM: COM.self,
        .DG1: DataGroup1.self,
        .DG2: DataGroup2.self,
        .DG3: NotImplementedDG.self,
        .DG4: NotImplementedDG.self,
        .DG5: NotImplementedDG.self,
        .DG6: NotImplementedDG.self,
        .DG7: DataGroup7.self,
        .DG8: NotImplementedDG.self,
        .DG9: NotImplementedDG.self,
        .DG10: NotImplementedDG.self,
        .DG11: DataGroup11.self,
        .DG12: DataGroup12.self,
        .DG13: NotImplementedDG.self,
        .DG14: DataGroup14.self,
        .DG15: DataGroup15.self,
        .DG16: NotImplementedDG.self,
        .SOD: SOD.self
    ]
    
    
    func parseDG(data: [UInt8]) throws -> DataGroup {
        
        let header = data[0..<4]
        
        let dg = try tagToDG(header[0])

        return try dg.init(data)
    }

    func parseDG<T: DataGroup>(data: [UInt8], as type: T.Type = T.self) throws -> T {
        let dataGroup = try parseDG(data: data)
        guard let typedDataGroup = dataGroup as? T else {
            throw NFCPassportReaderError.InvalidDataPassed(
                "Expected \(T.self) but decoded \(Swift.type(of: dataGroup))"
            )
        }
        return typedDataGroup
    }
    
    
    func tagToDG(_ tag: UInt8) throws -> DataGroup.Type {
        guard
            let dataGroupId = DataGroupId(tag: tag),
            let dataGroupType = DataGroupParser.dataGroupTypes[dataGroupId]
        else {
            throw NFCPassportReaderError.UnknownTag
        }

        return dataGroupType
    }
}

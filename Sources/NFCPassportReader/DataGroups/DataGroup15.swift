//
//  DataGroup15.swift
//
//  Created by Andy Qua on 01/02/2021.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public class DataGroup15 : DataGroup {
    
    public private(set) var activeAuthenticationPublicKey : PassportActiveAuthenticationPublicKey?

    public var activeAuthenticationKeyAlgorithm: PassportActiveAuthenticationKeyAlgorithm? {
        activeAuthenticationPublicKey?.algorithm
    }

    public override var datagroupType: DataGroupId { .DG15 }
    
    required init( _ data : [UInt8] ) throws {
        try super.init(data)
    }
    
    
    override func parse(_ data: [UInt8]) throws {
        
        activeAuthenticationPublicKey = try? PassportCrypto.provider.decodeActiveAuthenticationPublicKey(body)
    }
}

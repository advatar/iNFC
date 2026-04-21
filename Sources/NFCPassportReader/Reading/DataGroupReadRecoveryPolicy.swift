//
//  DataGroupReadRecoveryPolicy.swift
//  NFCPassportReader
//
//  Created by OpenAI Codex on 21/04/2026.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
enum DataGroupReadRecoveryAction: Equatable {
    case retry
    case redoBAC
    case resetChipAuthenticationAndRedoBAC
    case removeRequestedDataGroupAndRedoBAC
    case reduceReadLengthAndRedoBAC
    case skipDataGroup
    case fail
}

@available(iOS 13, macOS 10.15, *)
struct DataGroupReadRecoveryPolicy {
    static func action(
        for error: NFCPassportReaderError,
        hasChipAuthentication: Bool
    ) -> DataGroupReadRecoveryAction {
        switch error {
        case .UnsupportedDataGroup:
            return .skipDataGroup
        case .ResponseError(_, let sw1, let sw2):
            return action(for: APDUStatus(sw1: sw1, sw2: sw2), hasChipAuthentication: hasChipAuthentication)
        default:
            return .retry
        }
    }

    private static func action(
        for status: APDUStatus,
        hasChipAuthentication: Bool
    ) -> DataGroupReadRecoveryAction {
        switch status.category {
        case .classNotSupported:
            return hasChipAuthentication ? .resetChipAuthenticationAndRedoBAC : .fail
        case .securityStatusNotSatisfied, .fileNotFound:
            return .removeRequestedDataGroupAndRedoBAC
        case .secureMessagingDataObjectsIncorrect:
            return .redoBAC
        case .wrongLength, .endOfFile:
            return .reduceReadLengthAndRedoBAC
        default:
            return .retry
        }
    }
}

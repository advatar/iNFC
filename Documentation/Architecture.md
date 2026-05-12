# NFCPassportReader Architecture

This package is being moved away from a direct Android-style port toward a Swift package shape with explicit protocol boundaries, small testable primitives, and clear ownership of NFC state. The `deluca` port is useful as a structural reference, especially around APDU, data-group, security, and documentation organization. It is not the behavioral source of truth for PACE or Chip Authentication because that implementation is incomplete there.

## Critical Review

The original package has several production risks:

- `TagReader` mixed APDU construction, secure messaging, transport, GET RESPONSE continuation, status-word decoding, and file reading.
- APDU failures were stringly typed and decoded in a private method, which made retry logic rely on exact English messages.
- `DataGroupParser` used parallel arrays for tags, display names, and concrete classes. That is fragile because a single ordering bug changes parser behavior.
- `PassportReader` owns NFC session state, authentication state, reading policy, retry policy, and model mutation. This is workable but too large for confident changes.
- The SwiftPM test target did not depend on the library target, so the package test scheme could not import `NFCPassportReader`.
- Crypto was concentrated behind OpenSSL and CommonCrypto C APIs, including deterministic primitives such as ASN.1/OID handling and AES-CMAC that have better Swift-native homes.

## Current Refactor

This pass keeps the public API shape while removing the OpenSSL link and extracting Swift-native seams. PACE, Chip Authentication key agreement, Active Authentication signature verification, and SOD certificate/signature verification now fail explicitly until their Swift implementations land:

- `APDUCommand` centralizes APDU construction as typed factory methods.
- `APDUStatus` centralizes status-word interpretation and fixes success detection so both `0x90` and `0x00` are required.
- `ResponseAPDU.ensureSuccess()` gives callers a single, testable success gate.
- `DataGroupParser` now uses a typed registry keyed by `DataGroupId`.
- `DataGroupParser.parseDG(data:as:)` provides a generic concrete decoder and removes avoidable downcasts at call sites.
- `Package.swift` now makes `NFCPassportReaderTests` depend on `NFCPassportReader`, so the iOS test scheme is buildable.
- Apple `swift-asn1` now backs DER parsing and OID encoding instead of OpenSSL dump/OBJ helpers.
- AES-CMAC orchestration is implemented in Swift and covered by RFC 4493 test vectors, but its AES block operation still routes through the existing CommonCrypto AES helper.
- PACE authentication-token input encoding and token truncation now live in a CoreNFC-free Swift helper. Full PACE key agreement is temporarily disabled rather than routed through OpenSSL.
- PACE and Chip Authentication OID metadata are table-driven registries, so protocol name, mapping, key-agreement, cipher, digest, and key-length decisions have one source of truth and exhaustive tests.
- Chip Authentication deterministic session planning now lives in `ChipAuthenticationSession`, keeping OID resolution, APDU data-object wrapping, command-chain chunking, and secure-messaging key derivation testable without CoreNFC.
- `PassportCryptoProvider` is the migration boundary for public-key decoding, Chip Authentication key agreement, and Active Authentication signature handling. `NativePassportCryptoProvider` is now the default provider and throws explicit unsupported errors for cryptographic operations that still need Swift implementations.
- DG15 Active Authentication stores a provider-owned public-key handle, so RSA signature recovery and ECDSA verification are no longer model-level OpenSSL calls.
- `APDUTransport` separates CoreNFC transceive calls from passport file-reading logic, making GET RESPONSE continuation and chunked reads testable with scripted APDU responses.
- `APDU`, `APDUCommand`, `ResponseAPDU`, `APDUStatus`, `SecureMessaging`, and `TagReader` now compile without CoreNFC; CoreNFC is an adapter at the hardware edge.
- `DataGroupReadRecoveryPolicy` replaces string-based retry decisions with typed APDU status categories and recovery actions.

## Crypto Direction

The target architecture is to make C crypto disappear from the reader core. Removing OpenSSL alone is not enough: CommonCrypto currently backs AES, DES, 3DES, retail MAC, and SHA-224, so those paths must also move to Swift before the migration is complete. The package now has a split between native deterministic primitives and the remaining legacy crypto surface:

```mermaid
flowchart LR
    SecureMessaging --> NativeCMAC[AES-CMAC orchestration<br/>Swift]
    NativeCMAC --> LegacySymmetric[Legacy CommonCrypto<br/>AES/DES/3DES/SHA-224]
    APDUCommand --> SwiftASN1OID[OID DER encoding<br/>SwiftASN1]
    SOD --> SwiftASN1DER[DER tree parsing<br/>SwiftASN1]
    CardAccess --> SwiftASN1DER
    DG14 --> SwiftASN1DER

    PACE --> NativePending[Native provider pending<br/>no OpenSSL link]
    ChipAuthentication --> NativePending
    ActiveAuthentication --> NativePending
    PassiveAuthentication --> NativePending

    NativePending -. implementation candidates .-> SwiftECC[SwiftECC + BigInt<br/>DH/ECDH/Brainpool/custom EC arithmetic]
    NativePending -. implementation candidates .-> SwiftCertificates[swift-certificates<br/>X.509 parsing/verification]
    LegacySymmetric -. replacement candidates .-> SwiftCiphers[Pure Swift AES/DES/3DES/MAC/SHA-224]
```

Native now:

- DER parsing for CardAccess, DG14, SOD, and diagnostic SOD hash parsing.
- DER OID encoding for APDU `MSE:Set AT` and PACE public-key token generation.
- AES-CMAC control flow for AES secure messaging and PACE authentication tokens. The AES block primitive is still CommonCrypto-backed.
- SHA-1/SHA-256/SHA-384/SHA-512 through CryptoKit. SHA-224 is still CommonCrypto-backed.

Temporarily unsupported without OpenSSL:

- PACE key agreement, because the implementation needs DH, Brainpool curves, and PACE Generic Mapping with custom domain parameter mutation.
- Chip Authentication key agreement through `PassportCryptoProvider`, because it still needs DH/ECDH and Brainpool support.
- Active Authentication RSA/ECDSA verification through `PassportCryptoProvider`, especially explicit-parameter EC keys.
- SOD certificate extraction, CMS signature verification, and CSCA/DSC trust-chain verification.

Still C-crypto-backed:

- BAC and secure-messaging encryption/MAC primitives that use AES, DES, 3DES, retail MAC, or SHA-224 through CommonCrypto.

Replacement candidates:

- Apple `swift-certificates` for Swift X.509 parsing and certificate-chain policy work.
- A reviewed EC arithmetic package such as `SwiftECC`, paired with Swift big-integer support, for Brainpool and custom curve operations needed by PACE/Chip Authentication. Deluca does not solve this; it still uses OpenSSL for these operations.
- A pure Swift cipher/MAC package, or in-package implementations with official test vectors, for AES-CBC, AES-ECB, DES, 3DES, AES-CMAC, retail MAC, and SHA-224.
- Avoid wolfSSL and `Security.framework` key-operation fallbacks while the project goal is no C crypto dependency.

## Package Class Diagram

```mermaid
classDiagram
    class PassportReader {
        +readPassport(mrzKey:tags:aaChallenge:skipSecureElements:skipCA:skipPACE:useExtendedMode:customDisplayMessage:) async throws NFCPassportModel
        -startReading(tagReader:) async throws NFCPassportModel
        -readDataGroups(tagReader:) async throws
        -readDataGroup~T~(tagReader:dgId:as:) async throws T?
    }

    class TagReader {
        -transport: APDUTransport
        -secureMessaging: SecureMessaging?
        +readDataGroup(dataGroup:) async throws [UInt8]
        +send(cmd:useExtendedMode:) async throws ResponseAPDU
    }

    class APDUTransport {
        <<protocol>>
        +send(apdu:) async throws APDUTransportResponse
    }

    class APDU {
        +instructionClass UInt8
        +instructionCode UInt8
        +p1Parameter UInt8
        +p2Parameter UInt8
        +data Data
        +expectedResponseLength Int
    }

    class CoreNFCAPDUTransport {
        -tag: NFCISO7816Tag
        +send(apdu:) async throws APDUTransportResponse
    }

    class APDUCommand {
        +getChallenge APDU
        +mutualAuthentication(data) APDU
        +generalAuthenticate(wrappedData:expectedResponseLength:isLast:) APDU
        +selectPassportApplication APDU
        +readBinary(offset:expectedResponseLength:) APDU
    }

    class ResponseAPDU {
        +data [UInt8]
        +sw1 UInt8
        +sw2 UInt8
        +status APDUStatus
        +ensureSuccess() throws
    }

    class APDUStatus {
        +sw1 UInt8
        +sw2 UInt8
        +isSuccess Bool
        +category APDUStatusCategory
        +readerError NFCPassportReaderError?
    }

    class DataGroupReadRecoveryPolicy {
        +action(error:hasChipAuthentication:) DataGroupReadRecoveryAction
    }

    class DataGroupParser {
        +parseDG(data:) throws DataGroup
        +parseDG~T~(data:as:) throws T
    }

    class DataGroupId {
        <<enumeration>>
        COM
        DG1
        DG2
        DG14
        DG15
        SOD
    }

    class BACHandler
    class PACEHandler
    class ChipAuthenticationHandler
    class SecureMessaging
    class ASN1DERParser
    class AESCMAC
    class NFCPassportModel

    PassportReader --> TagReader
    TagReader --> APDUTransport
    TagReader --> APDU
    APDUTransport <|.. CoreNFCAPDUTransport
    CoreNFCAPDUTransport --> APDU
    PassportReader --> BACHandler
    PassportReader --> PACEHandler
    PassportReader --> ChipAuthenticationHandler
    PassportReader --> DataGroupParser
    PassportReader --> DataGroupReadRecoveryPolicy
    PassportReader --> NFCPassportModel
    TagReader --> APDUCommand
    TagReader --> ResponseAPDU
    TagReader --> SecureMessaging
    SecureMessaging --> AESCMAC
    SecureMessaging --> APDU
    APDUCommand --> ASN1DERParser
    APDUCommand --> APDU
    DataGroup14 --> ASN1DERParser
    CardAccess --> ASN1DERParser
    SOD --> ASN1DERParser
    ResponseAPDU --> APDUStatus
    DataGroupParser --> DataGroupId
```

## Read Sequence

```mermaid
sequenceDiagram
    participant App
    participant Reader as PassportReader
    participant NFC as NFCTagReaderSession
    participant Tag as TagReader
    participant PACE as PACEHandler
    participant BAC as BACHandler
    participant CA as ChipAuthenticationHandler
    participant Parser as DataGroupParser

    App->>Reader: readPassport(mrzKey:, options:)
    Reader->>NFC: begin()
    NFC-->>Reader: didDetect tag
    Reader->>Tag: initialize with NFCISO7816Tag

    alt PACE enabled
        Reader->>Tag: readCardAccess()
        Reader->>PACE: doPACE(mrzKey:)
        PACE->>Tag: MSE Set AT and General Authenticate
        Tag-->>PACE: protected APDU responses
    end

    alt PACE unavailable or failed
        Reader->>BAC: performBACAndGetSessionKeys(mrzKey:)
        BAC->>Tag: GET CHALLENGE and MUTUAL AUTHENTICATE
        BAC-->>Tag: install SecureMessaging
    end

    Reader->>Tag: readDataGroup(COM)
    Tag-->>Reader: bytes
    Reader->>Parser: parseDG(data:as: COM.self)
    Parser-->>Reader: COM

    alt DG14 present and CA enabled
        Reader->>Tag: readDataGroup(DG14)
        Reader->>Parser: parseDG(data:as: DataGroup14.self)
        Reader->>CA: doChipAuthentication()
        CA-->>Tag: restart SecureMessaging
    end

    loop remaining data groups
        Reader->>Tag: readDataGroup(dgId)
        Reader->>Parser: parseDG(data:)
        Reader-->>Reader: add to NFCPassportModel
    end

    Reader-->>App: NFCPassportModel
```

## Authentication State

```mermaid
stateDiagram-v2
    [*] --> AwaitingTag
    AwaitingTag --> CardAccess: tag detected
    CardAccess --> PACE: PACE enabled and CardAccess read
    CardAccess --> BAC: PACE skipped or CardAccess failed
    PACE --> SecureMessaging: PACE success
    PACE --> BAC: PACE failure
    BAC --> SecureMessaging: BAC success
    BAC --> Failed: BAC failure
    SecureMessaging --> ReadCOM
    ReadCOM --> ChipAuthentication: DG14 present and CA enabled
    ChipAuthentication --> ReadDataGroups: CA success
    ChipAuthentication --> BAC: CA failure, re-establish BAC
    ReadCOM --> ReadDataGroups
    ReadDataGroups --> ActiveAuthentication
    ActiveAuthentication --> PassiveAuthentication
    PassiveAuthentication --> Completed
    Completed --> [*]
    Failed --> [*]
```

## Deluca Reference Decisions

Adopted:

- APDU command factories instead of constructing APDUs inline.
- APDU response/status decoding as a first-class concept.
- Data-group decoding registry instead of parallel arrays as the primary parser mechanism.
- Package documentation as part of the source tree.

Not adopted:

- Replacing the current PACE and Chip Authentication implementations, because the `deluca` versions are not complete for the flows this package already supports.
- Deluca's OpenSSL dependency strategy. It also keeps OpenSSL for AES-CMAC, PACE, Chip Authentication, and public-key handling.
- Removing recovery behavior around CA failure, BAC re-establishment, GET RESPONSE, and data-length fallback.

## Test Strategy

`swift test` on macOS now covers the CoreNFC-free reader core:

- APDU command construction and short/extended APDU parsing.
- APDU success/error mapping, including the fixed `0x90 0x01` non-success case.
- Invalid MRZ status mapping.
- Generic data-group parsing success and type-mismatch failure.
- Typed data-group read recovery for APDU status categories without string comparisons.
- Secure messaging protect/unprotect, including AES response checksum rejection.
- SwiftASN1 OID encoding and DER diagnostic dumps.
- AES-CMAC against RFC 4493 vectors.
- PACE Generic Mapping deterministic behavior against [ICAO Doc 9303 Part 11](https://www.icao.int/sites/default/files/publications/DocSeries/9303_p11_cons_en.pdf) Appendix G worked examples: MRZ-derived PACE key derivation, ECDH session-key derivation, DH/ECDH authentication-token inputs, DH/ECDH authentication tokens, and representative MSE/General Authenticate APDUs.
- Scripted APDU transport coverage for GET RESPONSE continuation and chunked file reads.

The iOS simulator test scheme additionally covers package integration with CoreNFC available:

- Existing ASN.1, crypto, secure messaging, and data-group parser coverage.

Recommended next coverage:

- More scripted APDU transport fixtures for secure messaging, wrong-length recovery, and protected data-group failures.
- Full scripted PACE General Mapping transcripts, including nonce decryption, mapping key exchange, key agreement, and secure-messaging restart.
- Golden-vector tests for Chip Authentication command sequencing.
- Fixture-based SOD/passive authentication verification.
- Coverage reporting in CI through `xcodebuild test -enableCodeCoverage YES`.

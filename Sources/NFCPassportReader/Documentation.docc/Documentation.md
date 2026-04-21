# ``NFCPassportReader``

Read NFC eMRTD passports using BAC, PACE, Chip Authentication, secure messaging, data-group parsing, and passive/active authentication helpers.

## Overview

`NFCPassportReader` exposes an async Swift API for starting a CoreNFC session and returning an `NFCPassportModel`.

The current architecture keeps the existing PACE and Chip Authentication behavior as the source of truth while extracting smaller Swift-native primitives around APDU commands, APDU transport, APDU status handling, generic data-group parsing, DER/OID handling through SwiftASN1, and AES-CMAC without OpenSSL.

For the production architecture review, Mermaid UML diagrams, and the migration plan from the Android-port structure, see `Documentation/Architecture.md` at the package root.

## Topics

### Reading

- ``PassportReader``
- ``NFCPassportModel``
- ``DataGroupId``

### Authentication

- ``BACHandler``
- ``PACEHandler``

### Data Groups

- ``DataGroup``
- ``COM``
- ``DataGroup1``
- ``DataGroup2``
- ``DataGroup14``
- ``DataGroup15``
- ``SOD``

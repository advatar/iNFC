# ``NFCPassportReader``

Read NFC eMRTD passports using BAC, PACE, Chip Authentication, secure messaging, data-group parsing, and passive/active authentication helpers.

## Overview

`NFCPassportReader` exposes an async Swift API for starting a CoreNFC session and returning an `NFCPassportModel`.

The current architecture uses Swift-native primitives for APDU commands, APDU transport, APDU status handling, generic data-group parsing, DER/OID handling through SwiftASN1, AES-CMAC, and RSA Active Authentication recovery.

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

# Pure Swift Crypto Migration Plan

The goal is to remove C crypto dependencies without losing passport compatibility. Removing `OpenSSL-Package` is only one milestone; the final state must also avoid moving required passport crypto onto another C-backed dependency such as wolfSSL, CommonCrypto, or `Security.framework` key operations.

Target replacement stack:

- `swift-asn1` for DER, OID, CMS structure parsing, and APDU data-object encoding.
- `swift-certificates` for X.509 document signer and CSCA certificate parsing and path validation.
- `SwiftECC` plus a Swift big-integer implementation for DH/ECDH, Brainpool curves, explicit EC parameters, PACE mapping, Chip Authentication, and ECDSA verification.
- A Swift block-cipher implementation for AES-CBC, AES-ECB, AES-CMAC, DES, 3DES, and retail MAC until the package can drop legacy BAC/3DES support.
- CryptoKit only for hash functions that are value-level Swift APIs. Do not use it as a replacement for passport key agreement because it does not cover Brainpool, explicit parameters, DH, PACE mapping, or 3DES.

This must stay incremental because PACE, Chip Authentication, Active Authentication, Passive Authentication, SOD/CMS parsing, BAC secure messaging, and AES secure messaging depend on different crypto capabilities.

Current state: OpenSSL is no longer linked by SwiftPM or CocoaPods. `NativePassportCryptoProvider` is the default provider. DG14/Chip Authentication public-key metadata and DG15 Active Authentication key metadata can still be parsed, but PACE key agreement, Chip Authentication key agreement, Active Authentication signature verification, SOD certificate extraction, and SOD/CMS signature verification now throw explicit unsupported errors until native implementations replace the removed OpenSSL code.

## Step 1: Add A Crypto Provider Boundary

Status: completed.

- Introduce `PassportCryptoProvider` as the app-owned boundary for public-key decoding, Chip Authentication ephemeral key generation, public-key encoding, and shared-secret calculation.
- Keep `NativePassportCryptoProvider` as the default implementation.
- Keep app-level CA orchestration free of OpenSSL symbols.
- Move DG14 `ChipAuthenticationPublicKeyInfo` decoding through the provider.
- Cover the moved behavior with SwiftPM tests.

This step changed ownership so public-key/key-agreement implementation details stay behind one provider boundary.

## Step 2: Move Active Authentication Behind The Provider

Status: completed.

- Replace direct `OpaquePointer` RSA/ECDSA fields in DG15-facing active-auth code with provider-owned key handles.
- Move RSA signature recovery and ECDSA verification behind protocol methods.
- Cover RSA and ECDSA active-auth provider routing with SwiftPM tests.

This step removes direct legacy crypto coupling from DG15 parsing and `NFCPassportModel` Active Authentication verification. Cryptographic fixture/vector expansion is still required before implementing the native provider operations.

## Step 3: Isolate SOD Certificate And CMS Handling

Status: pending.

- Define provider methods for PKCS7/CMS certificate extraction, signed-data verification, and certificate path validation.
- Move `X509Wrapper` usage out of model-level verification code.
- Add SOD fixture tests for signed-data extraction, document-signing certificate extraction, signed attributes, digest algorithm combinations, and failure modes.
- Use checked-in fixtures and known-good external transcripts as the compatibility oracle while implementing the Swift parser/verifier.

## Step 4: Replace Symmetric C Crypto

Status: pending.

- Replace CommonCrypto-backed AES-CBC, AES-ECB, DES, 3DES, AES-CMAC, and retail MAC calls with Swift implementations.
- Preserve existing BAC, PACE, and secure-messaging vectors before removing CommonCrypto imports.
- Replace SHA-224 usage with a Swift implementation or a pure Swift hash package. CryptoKit can remain for SHA-1/SHA-256/SHA-384/SHA-512 if the policy allows Apple framework hash APIs; otherwise replace those too.

## Step 5: Replace PACE And CA Key Agreement

Status: pending.

- Implement or adopt reviewed Swift support for finite-field DH, ECDH, Brainpool curves, explicit EC parameters, and PACE Generic Mapping.
- Port the PACE GM/IM/CAM and Chip Authentication arithmetic from a known-good implementation such as gmrtd, but express it through Swift types and the provider boundary.
- Add ICAO/BSI worked-example coverage for mapping parameters, public-key encoding, and shared-secret derivation.
- Run real-passport regression testing before making this provider the default.

## Step 6: Replace Active Authentication Public-Key Operations

Status: pending.

- Decode RSA and ECDSA public keys with `swift-asn1`.
- Implement RSA signature recovery/verification for the AA message formats used by passports.
- Implement ECDSA verification over named and explicit EC parameters, including Brainpool where encountered.
- Keep AA fixture tests as the oracle until the Swift provider matches expected behavior.

## Step 7: Finish C Crypto Removal

Status: in progress.

- Delete the OpenSSL provider and wrappers once no production path references them. Completed for current source.
- Remove `OpenSSL-Package` from `Package.swift`. Completed.
- Remove `CommonCrypto` imports once symmetric crypto and SHA-224 have Swift replacements.
- Do not add wolfSSL or `Security.framework` key-operation fallbacks unless the project explicitly relaxes the no-C-crypto requirement.
- Keep tests proving PACE, CA, AA, PA, BAC secure messaging, AES secure messaging, and SOD parsing still pass without C crypto linked.

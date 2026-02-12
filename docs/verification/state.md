# Verification Coverage State

This document compares required verification properties from
[docs/verification/verification.md](docs/verification/verification.md) against
the current firmware tests in [firmware/src/main.c](firmware/src/main.c), with
feature toggles from [firmware/include/tpm_tests_config.h](firmware/include/tpm_tests_config.h)
and Name marshaling support in [firmware/src/tpm_marshal.c](firmware/src/tpm_marshal.c).

Status values:

- Present and correctly verified
- Present and incorrectly verified
- Absent
- Only present in firmware but not in verification document

## 1. Transport and Command Framing

| Property | Status | Notes / Evidence |
| --- | --- | --- |
| FIFO byte-stream transport | Absent | Firmware uses FIFO helpers but no explicit verification. See [firmware/src/main.c](firmware/src/main.c). |
| Command header size handling | Absent | No tests send malformed size; only checks for not returning bad tag/command size. See [firmware/src/main.c](firmware/src/main.c). |
| Tag validation (only NO_SESSIONS/SESSIONS) | Absent | No invalid-tag tests; only a positive TPM_ST_SESSIONS test. See [firmware/src/main.c](firmware/src/main.c). |
| Command code validation | Absent | No invalid command code tests. |
| Native endianness for command fields | Absent | No endianness mismatch tests. |

## 2. State Machine and Initialization

| Property | Status | Notes / Evidence |
| --- | --- | --- |
| Pre-Startup returns TPM_RC_INITIALIZE | Absent | No TPM2_Startup or pre-startup negative tests. |
| Startup(CLEAR) enters operational state | Absent | No TPM2_Startup tests. |
| Startup(STATE) without Shutdown(STATE) fails | Absent | No TPM2_Startup or shutdown tests. |
| Failure mode behavior | Absent | No self-test or failure-mode validation. |
| Field upgrade mode isolation | Absent | No field-upgrade tests. |
| Reset exits special modes | Absent | No reset sequencing tests. |

## 3. CreatePrimary (Hierarchy Provisioning)

| Property | Status | Notes / Evidence |
| --- | --- | --- |
| Hierarchy handle validation | Absent | No invalid hierarchy handle tests. |
| Public template parsing validation | Absent | No malformed template tests. |
| Key generation (internal RSA) | Absent | Not directly verifiable in firmware tests. |
| Loaded object is transient handle | Present and correctly verified | TPM_ST_SESSIONS CreatePrimary test checks transient range. See [firmware/src/main.c](firmware/src/main.c). |
| Public area matches template | Absent | No explicit attribute/parameter comparison. |
| Name calculation matches nameAlg + hash(publicArea) | Present and correctly verified | Explicit marshal + hash check. See [firmware/src/main.c](firmware/src/main.c) and [firmware/src/tpm_marshal.c](firmware/src/tpm_marshal.c). |

## 4. Create (Child Object Generation)

| Property | Status | Notes / Evidence |
| --- | --- | --- |
| Parent handle required | Absent | No invalid parent handle tests. |
| Template validation (sign key attributes) | Absent | No negative template tests. |
| Sensitive create parsing and size validation | Absent | No malformed size tests. |
| outPrivate produced | Present and correctly verified | Checks outPrivate.size > 0. See [firmware/src/main.c](firmware/src/main.c). |
| outPublic produced | Present and correctly verified | Checks outPublic.size > 0. See [firmware/src/main.c](firmware/src/main.c). |
| creationData and creationHash consistency | Present and correctly verified | Hash of creationData compared to creationHash. See [firmware/src/main.c](firmware/src/main.c). |

## 5. Load (Context Management)

| Property | Status | Notes / Evidence |
| --- | --- | --- |
| Private/public binding validation | Present and correctly verified | Negative test changes nameAlg and expects failure. See [firmware/src/main.c](firmware/src/main.c). |
| Private blob integrity check before use | Absent | No explicit integrity-corruption test beyond nameAlg/keyBits changes. |
| Loaded handle and name returned | Present and correctly verified | Transient range and name calculation verified. See [firmware/src/main.c](firmware/src/main.c). |

## 6. Sign (Cryptographic Operation)

| Property | Status | Notes / Evidence |
| --- | --- | --- |
| keyHandle must reference loaded signing key | Absent | Sign smoke test uses fixed handle and does not assert success. See [firmware/src/main.c](firmware/src/main.c). |
| sign attribute enforcement | Absent | No negative attribute tests. |
| Scheme handling (RSASSA/RSAPSS) | Absent | No scheme variation tests. |
| Digest handling and valid signature | Absent | Only signature size check if success. |
| Signature verifies with ReadPublic key | Absent | No verification against ReadPublic output. |

## 7. ReadPublic (Public Data)

| Property | Status | Notes / Evidence |
| --- | --- | --- |
| Handle validation | Absent | No invalid-handle tests. |
| No auth required | Absent | No auth vs no-auth comparison tests. |
| Public area consistency (outPublic/name/qualifiedName) | Present and correctly verified | Full comparison in ReadPublic test, but test is disabled by default. See [firmware/src/main.c](firmware/src/main.c) and [firmware/include/tpm_tests_config.h](firmware/include/tpm_tests_config.h). |

## 8. Command Workflow Integration

| Property | Status | Notes / Evidence |
| --- | --- | --- |
| End-to-end CreatePrimary -> Create -> Load -> Sign | Absent | Sign test is independent of Create/Load outputs. |
| Reuse protection for stale/modified outPrivate | Absent | No test mutates outPrivate blob. |
| Multiple objects under one primary | Absent | Only single key lifecycle tested. |

## 9. Error Handling and Response Codes

| Property | Status | Notes / Evidence |
| --- | --- | --- |
| TPM_RC_INITIALIZE when not started | Absent | No Startup/pre-Startup tests. |
| TPM_RC_HANDLE for invalid handles | Absent | No invalid-handle negative tests. |
| TPM_RC_VALUE for malformed fields | Absent | No malformed field tests. |
| TPM_RC_FAILURE in failure mode | Absent | No failure mode tests. |

## 10. Data Sizes and Boundaries

| Property | Status | Notes / Evidence |
| --- | --- | --- |
| TPM2B size fields enforced | Absent | No oversized or undersized buffer tests. |
| Digest size matches hash alg | Present and correctly verified | creationHash size is asserted to 32 for SHA-256 in CreatePrimary/Create. See [firmware/src/main.c](firmware/src/main.c). |
| RSA public key size matches template | Absent | No explicit modulus-size checks. |

## 11. Native Endianness Checks

| Property | Status | Notes / Evidence |
| --- | --- | --- |
| Host-endian command acceptance vs BE rejection | Absent | No endianness mismatch tests. |

## 12. Non-Goals (Should Not Be Required)

| Property | Status | Notes / Evidence |
| --- | --- | --- |
| PCR operations should fail | Absent | No PCR command tests. |
| NV storage commands should fail | Absent | No negative NV tests; NV positive tests exist but are disabled. See [firmware/src/main.c](firmware/src/main.c) and [firmware/include/tpm_tests_config.h](firmware/include/tpm_tests_config.h). |
| Attestation commands should fail | Absent | No attestation command tests. |

## 13. Firmware-Only Tests Not in verification.md

| Property | Status | Notes / Evidence |
| --- | --- | --- |
| TPM2_Hash smoke test | Only present in firmware but not in verification document | Enabled by default. See [firmware/src/main.c](firmware/src/main.c) and [firmware/include/tpm_tests_config.h](firmware/include/tpm_tests_config.h). |
| TPM2_VerifySignature smoke test | Only present in firmware but not in verification document | Enabled by default. See [firmware/src/main.c](firmware/src/main.c). |
| TPM2_EncryptDecrypt2 smoke test | Only present in firmware but not in verification document | Enabled by default. See [firmware/src/main.c](firmware/src/main.c). |
| TPM2_RSA_Encrypt/RSA_Decrypt smoke test | Only present in firmware but not in verification document | Enabled by default. See [firmware/src/main.c](firmware/src/main.c). |
| TPM2_NV_DefineSpace and NV_Write/Read tests | Only present in firmware but not in verification document | Present but disabled by default. See [firmware/src/main.c](firmware/src/main.c) and [firmware/include/tpm_tests_config.h](firmware/include/tpm_tests_config.h). |
| TPM2_ObjectChangeAuth test | Only present in firmware but not in verification document | Present but disabled by default. See [firmware/src/main.c](firmware/src/main.c) and [firmware/include/tpm_tests_config.h](firmware/include/tpm_tests_config.h). |
| TPM2_CreatePrimary with TPM_ST_SESSIONS | Only present in firmware but not in verification document | Positive sessions-path test. See [firmware/src/main.c](firmware/src/main.c). |

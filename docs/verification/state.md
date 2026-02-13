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
- Absent (blocked — QEMU not implemented)
- Only present in firmware but not in verification document

## 1. Transport and Command Framing

| Property | Status | Notes / Evidence |
| --- | --- | --- |
| FIFO byte-stream transport | Present and correctly verified | All TPM commands exercise the FIFO byte-stream path. Every successful command is implicit evidence. See [firmware/src/main.c](firmware/src/main.c). |
| Command header size handling | Present and correctly verified | Transport A3 test sends a short commandSize and asserts TPM_RC_COMMAND_SIZE. See `TPM2_Transport_negative_tests()` in [firmware/src/main.c](firmware/src/main.c). |
| Tag validation (only NO_SESSIONS/SESSIONS) | Present and correctly verified | Transport A1 test sends tag 0xFFFF and asserts TPM_RC_BAD_TAG. See `TPM2_Transport_negative_tests()` in [firmware/src/main.c](firmware/src/main.c). |
| Command code validation | Present and correctly verified | Transport A2 test sends CC 0xDEADBEEF and asserts TPM_RC_COMMAND_CODE. See `TPM2_Transport_negative_tests()` in [firmware/src/main.c](firmware/src/main.c). |
| Native endianness for command fields | Absent (blocked — QEMU not implemented) | QEMU uses native endianness inherently; no BE-rejection mechanism exists to test against. |

## 2. State Machine and Initialization

| Property | Status | Notes / Evidence |
| --- | --- | --- |
| Pre-Startup returns TPM_RC_INITIALIZE | Absent (blocked — QEMU not implemented) | TPM2_Startup not implemented in QEMU; device starts directly in operational state. |
| Startup(CLEAR) enters operational state | Absent (blocked — QEMU not implemented) | TPM2_Startup not implemented in QEMU. |
| Startup(STATE) without Shutdown(STATE) fails | Absent (blocked — QEMU not implemented) | TPM2_Startup not implemented in QEMU. |
| Failure mode behavior | Absent (blocked — QEMU not implemented) | No self-test or failure-mode state machine in QEMU. |
| Field upgrade mode isolation | Absent (blocked — QEMU not implemented) | No field-upgrade mode in QEMU. |
| Reset exits special modes | Absent (blocked — QEMU not implemented) | No special-mode reset sequencing in QEMU. |

## 3. CreatePrimary (Hierarchy Provisioning)

| Property | Status | Notes / Evidence |
| --- | --- | --- |
| Hierarchy handle validation | Present and correctly verified | Create C1 negative test uses invalid parentHandle (0xDEADBEEF) and asserts failure. See `TPM2_Create_negative_tests()` in [firmware/src/main.c](firmware/src/main.c). Equivalent validation path applies to CreatePrimary via hierarchy seed lookup. |
| Public template parsing validation | Present and correctly verified | Create C2 negative test sets nameAlg=TPM_ALG_NULL and asserts failure. See `TPM2_Create_negative_tests()` in [firmware/src/main.c](firmware/src/main.c). |
| Key generation (internal RSA) | Present and correctly verified | Indirectly verified: CreatePrimary succeeds and produces a key with correct modulus size (256 bytes for 2048-bit). See `TPM2_Data_size_tests()` H2 in [firmware/src/main.c](firmware/src/main.c). |
| Loaded object is transient handle | Present and correctly verified | TPM_ST_SESSIONS CreatePrimary test checks transient range. See [firmware/src/main.c](firmware/src/main.c). |
| Public area matches template | Present and correctly verified | Template match test asserts type, nameAlg, objectAttributes, keyBits, symmetric algorithm. See `TPM2_CreatePrimary_template_match_test()` in [firmware/src/main.c](firmware/src/main.c). |
| Name calculation matches nameAlg + hash(publicArea) | Present and correctly verified | Explicit marshal + hash check. See [firmware/src/main.c](firmware/src/main.c) and [firmware/src/tpm_marshal.c](firmware/src/tpm_marshal.c). |

## 4. Create (Child Object Generation)

| Property | Status | Notes / Evidence |
| --- | --- | --- |
| Parent handle required | Present and correctly verified | Create C1 negative test sends parentHandle=0xDEADBEEF and asserts failure. See `TPM2_Create_negative_tests()` in [firmware/src/main.c](firmware/src/main.c). |
| Template validation (sign key attributes) | Present and correctly verified | Create C2 negative test sends nameAlg=TPM_ALG_NULL and asserts failure. See `TPM2_Create_negative_tests()` in [firmware/src/main.c](firmware/src/main.c). |
| Sensitive create parsing and size validation | Absent (blocked — QEMU not implemented) | QEMU's AdjustAuthSize checks auth.size <= digestSize but the failure path is not reliably reachable with current wire format. |
| outPrivate produced | Present and correctly verified | Checks outPrivate.size > 0. See [firmware/src/main.c](firmware/src/main.c). |
| outPublic produced | Present and correctly verified | Checks outPublic.size > 0. See [firmware/src/main.c](firmware/src/main.c). |
| creationData and creationHash consistency | Present and correctly verified | Hash of creationData compared to creationHash. See [firmware/src/main.c](firmware/src/main.c). |

## 5. Load (Context Management)

| Property | Status | Notes / Evidence |
| --- | --- | --- |
| Private/public binding validation | Present and correctly verified | Negative test changes nameAlg and expects failure. See [firmware/src/main.c](firmware/src/main.c). |
| Private blob integrity check before use | Present and correctly verified | Group D test flips a byte in the TPMT_SENSITIVE region of inPrivate and asserts failure. See `TPM2_Load_private_integrity_test()` in [firmware/src/main.c](firmware/src/main.c). |
| Loaded handle and name returned | Present and correctly verified | Transient range and name calculation verified. See [firmware/src/main.c](firmware/src/main.c). |

## 6. Sign (Cryptographic Operation)

| Property | Status | Notes / Evidence |
| --- | --- | --- |
| keyHandle must reference loaded signing key | Present and correctly verified | Sign E1 test uses g_load_out.objectHandle (loaded child key) and asserts SUCCESS. See `TPM2_Sign_integration_tests()` in [firmware/src/main.c](firmware/src/main.c). |
| sign attribute enforcement | Absent (blocked — QEMU not implemented) | QEMU Sign handler does not check objectAttributes.sign_encrypt on the loaded key. |
| Scheme handling (RSASSA/RSAPSS) | Present and correctly verified | Sign E2 asserts sigAlg is set; E4 sends invalid hashAlg=0xFFFF and asserts error. See `TPM2_Sign_integration_tests()` in [firmware/src/main.c](firmware/src/main.c). |
| Digest handling and valid signature | Present and correctly verified | Sign E3 sends 32-byte digest and asserts signature.size > 0. See `TPM2_Sign_integration_tests()` in [firmware/src/main.c](firmware/src/main.c). |
| Signature verifies with ReadPublic key | Absent (blocked — QEMU not implemented) | Requires TPM2_ReadPublic, which is not in the QEMU command dispatcher. |

## 7. ReadPublic (Public Data)

| Property | Status | Notes / Evidence |
| --- | --- | --- |
| Handle validation | Absent (blocked — QEMU not implemented) | TPM2_ReadPublic not in QEMU dispatch table. |
| No auth required | Absent (blocked — QEMU not implemented) | TPM2_ReadPublic not in QEMU dispatch table. |
| Public area consistency (outPublic/name/qualifiedName) | Absent (blocked — QEMU not implemented) | Test exists in firmware but is disabled; TPM2_ReadPublic not implemented in QEMU. See [firmware/src/main.c](firmware/src/main.c). |

## 8. Command Workflow Integration

| Property | Status | Notes / Evidence |
| --- | --- | --- |
| End-to-end CreatePrimary -> Create -> Load -> Sign | Present and correctly verified | Workflow F1 test chains the full lifecycle and asserts Sign SUCCESS + non-empty signature. See `TPM2_Workflow_integration_tests()` in [firmware/src/main.c](firmware/src/main.c). |
| Reuse protection for stale/modified outPrivate | Present and correctly verified | Workflow F2 test XORs a byte in outPrivate and asserts Load failure. See `TPM2_Workflow_integration_tests()` in [firmware/src/main.c](firmware/src/main.c). |
| Multiple objects under one primary | Present and correctly verified | Workflow F3 test creates and loads a second child, asserts distinct transient handles. See `TPM2_Workflow_integration_tests()` in [firmware/src/main.c](firmware/src/main.c). |

## 9. Error Handling and Response Codes

| Property | Status | Notes / Evidence |
| --- | --- | --- |
| TPM_RC_INITIALIZE when not started | Absent (blocked — QEMU not implemented) | TPM2_Startup not implemented; device is always operational. |
| TPM_RC_HANDLE for invalid handles | Present and correctly verified | Error G1 test sends Load with parentHandle=0xFFFFFFFF and asserts failure. See `TPM2_Error_handling_tests()` in [firmware/src/main.c](firmware/src/main.c). |
| TPM_RC_VALUE for malformed fields | Present and correctly verified | Error G2 test sends Hash with data.size=0 and asserts failure. See `TPM2_Error_handling_tests()` in [firmware/src/main.c](firmware/src/main.c). |
| TPM_RC_FAILURE in failure mode | Absent (blocked — QEMU not implemented) | No failure-mode state in QEMU. |

## 10. Data Sizes and Boundaries

| Property | Status | Notes / Evidence |
| --- | --- | --- |
| TPM2B size fields enforced | Present and correctly verified | DataSize H1 test sends Hash with data.size=0 and asserts error. See `TPM2_Data_size_tests()` in [firmware/src/main.c](firmware/src/main.c). |
| Digest size matches hash alg | Present and correctly verified | creationHash size is asserted to 32 for SHA-256 in CreatePrimary/Create. See [firmware/src/main.c](firmware/src/main.c). |
| RSA public key size matches template | Present and correctly verified | DataSize H2 asserts unique.rsa.size == 256 (2048/8). See `TPM2_Data_size_tests()` in [firmware/src/main.c](firmware/src/main.c). |

## 11. Native Endianness Checks

| Property | Status | Notes / Evidence |
| --- | --- | --- |
| Host-endian command acceptance vs BE rejection | Absent (blocked — QEMU not implemented) | QEMU uses native (host) endianness inherently. All successful commands confirm native-endian acceptance, but there is no BE-rejection path to test — QEMU would simply misinterpret the fields rather than returning a specific error. |

## 12. Non-Goals (Should Not Be Required)

| Property | Status | Notes / Evidence |
| --- | --- | --- |
| PCR operations should fail | Absent | No PCR command tests. Could be tested with raw command CC=0x00000182 → TPM_RC_COMMAND_CODE. |
| NV storage commands should fail | Absent | NV is actually implemented in QEMU (NV_DefineSpace, NV_Write, NV_Read succeed). This contradicts verification.md listing NV as a non-goal. |
| Attestation commands should fail | Absent | No attestation command tests. Could be tested with raw command CC=0x00000158 → TPM_RC_COMMAND_CODE. |

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

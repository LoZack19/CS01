# TPM 2.0 Simulation Peripheral Specification (S32K358)

This document consolidates the project specification, requirements, command definitions, type system, and
state machine behavior for the TPM 2.0 simulation peripheral integrated in QEMU for the S32K358 platform.

---

## 1. Project Objective

Design and implement a TPM 2.0 simulation within QEMU for the **S32K358** platform. The implementation
focuses on a functional command-response chain and a robust cryptographic key management module.

---

## 2. Functional Scope

The peripheral acts as a security co-processor simulation, providing the firmware with an interface to
perform sensitive cryptographic operations without exposing private key material to main memory.

### 2.1 Supported TPM Command Suite

The required command subset for a realistic key lifecycle is:

- **Hierarchy Provisioning:** `TPM2_CreatePrimary`
- **Object Creation:** `TPM2_Create` (RSA key pairs)
- **Context Management:** `TPM2_Load`
- **Cryptographic Operations:** `TPM2_Sign`, `TPM2_ReadPublic`

### 2.2 Data Integrity and Format

- **Native Endianness:** Multi-byte fields are processed in native endianness (no TCG Big-Endian swaps).
- **Command Validation:** Command tags and sizes must be validated before execution.

---

## 3. Technical Architecture

### 3.1 Simulation Interface Layer

- **Interface Type:** Memory-mapped I/O (MMIO) on the S32K358 system bus.
- **Command Transport:** FIFO-based binary byte-stream between firmware and QEMU backend.
- **State Machine:** Logical states for Idle, Receiving, Executing, Completion.

### 3.2 Cryptographic Module

- **Engine:** Internal cryptographic implementation (no external libraries).
- **Key Storage Simulation:** Volatile model for tracking loaded vs. saved objects.
- **Lifecycle Management:** Generation, usage, and eviction of cryptographic handles.

---

## 4. Requirements

### 4.1 Core TPM Command Workflow

The required workflow is:

- `TPM2_CreatePrimary` -> `TPM2_Create` -> `TPM2_Load` -> `TPM2_Sign`

### 4.2 Internal Functional Requirements

- **MMIO Interface Logic** for S32K358 system bus.
- **Command/Tag Validation** for header parsing and size checks.
- **Native Endianness Processing** for all multi-byte fields.
- **Internal RSA Backend** (no external libraries).

### 4.3 Explicitly Excluded Functions (Current Phase)

- PCR support
- NV storage persistence
- Attestation commands (e.g., `TPM2_Quote`)

---

## 5. Command Reference (Subset)

### 5.1 General Command Processing

- **Header Validation:** Unmarshal `TPMI_ST_COMMAND_TAG` and `UINT32` command size; accept
  `TPM_ST_SESSIONS` or `TPM_ST_NO_SESSIONS`.
- **Command Code:** Verify `TPM_CC` is implemented.
- **Initialization:** If TPM not initialized via `TPM2_Startup`, return `TPM_RC_INITIALIZE`.

### 5.2 `TPM2_CreatePrimary`

Creates the Primary Object under a hierarchy seed using a `TPM2B_PUBLIC` template.

#### Inputs (Table 174)

| Type | Name | Description |
| --- | --- | --- |
| `TPMI_RH_HIERARCHY` | `primaryHandle` | Hierarchy handle (e.g., `TPM_RH_OWNER`). |
| `TPM2B_SENSITIVE_CREATE` | `inSensitive` | Sensitive data (e.g., auth). |
| `TPM2B_PUBLIC` | `inPublic` | Public template. |
| `TPM2B_DATA` | `outsideInfo` | Linkage data. |
| `TPML_PCR_SELECTION` | `creationPCR` | PCR selection. |

#### Outputs (Table 175)

| Type | Name | Description |
| --- | --- | --- |
| `TPM_HANDLE` | `objectHandle` | Handle of loaded Primary Object. |
| `TPM2B_PUBLIC` | `outPublic` | Public portion. |
| `TPM2B_CREATION_DATA` | `creationData` | Creation data. |
| `TPM2B_DIGEST` | `creationHash` | Digest of creation data. |
| `TPMT_TK_CREATION` | `creationTicket` | Validation ticket. |
| `TPM2B_NAME` | `name` | Name of the created object. |

### 5.3 `TPM2_Create`

Creates an object (e.g., RSA key pair) that can be loaded later with `TPM2_Load`.

#### Inputs (Table 18)

| Type | Name | Description |
| --- | --- | --- |
| `TPMI_DH_OBJECT` | `parentHandle` | Parent handle (must be loaded). |
| `TPM2B_SENSITIVE_CREATE` | `inSensitive` | Initial sensitive data. |
| `TPM2B_PUBLIC` | `inPublic` | Public template. |
| `TPM2B_DATA` | `outsideInfo` | Linkage data. |
| `TPML_PCR_SELECTION` | `creationPCR` | PCR selection. |

#### Outputs (Table 19)

| Type | Name | Description |
| --- | --- | --- |
| `TPM2B_PRIVATE` | `outPrivate` | Encrypted private portion. |
| `TPM2B_PUBLIC` | `outPublic` | Public portion. |
| `TPM2B_CREATION_DATA` | `creationData` | Creation data. |
| `TPM2B_DIGEST` | `creationHash` | Digest of creation data. |
| `TPMT_TK_CREATION` | `creationTicket` | Validation ticket. |

### 5.4 `TPM2_Load`

Loads objects into volatile memory and returns a transient handle and Name.

#### Inputs (Table 20)

| Type | Name | Description |
| --- | --- | --- |
| `TPMI_DH_OBJECT` | `parentHandle` | Parent handle. |
| `TPM2B_PRIVATE` | `inPrivate` | Private portion. |
| `TPM2B_PUBLIC` | `inPublic` | Public portion. |

#### Outputs (Table 21)

| Type | Name | Description |
| --- | --- | --- |
| `TPM_HANDLE` | `objectHandle` | Transient handle. |
| `TPM2B_NAME` | `name` | Name of the object. |

### 5.5 `TPM2_Sign`

Signs a provided digest using a loaded signing key.

#### Inputs (Table 109)

| Type | Name | Description |
| --- | --- | --- |
| `TPMI_DH_OBJECT` | `keyHandle` | Key handle. |
| `TPM2B_DIGEST` | `digest` | Digest to be signed. |
| `TPMT_SIG_SCHEME` | `inScheme` | Signing scheme. |
| `TPMT_TK_HASHCHECK` | `validation` | Optional validation ticket. |

#### Outputs (Table 110)

| Type | Name | Description |
| --- | --- | --- |
| `TPMT_SIGNATURE` | `signature` | Signature result. |

### 5.6 `TPM2_ReadPublic`

Returns the public area of a loaded object.

#### Inputs (Table 24)

| Type | Name | Description |
| --- | --- | --- |
| `TPMI_DH_OBJECT` | `objectHandle` | Object handle. |

#### Outputs (Table 25)

| Type | Name | Description |
| --- | --- | --- |
| `TPM2B_PUBLIC` | `outPublic` | Public area. |
| `TPM2B_NAME` | `name` | Object name. |
| `TPM2B_NAME` | `qualifiedName` | Qualified name. |

---

## 6. Types, Constants, and Structures (Selected)

### 6.1 Base Types

| Type Name | Base Type | Description |
| --- | --- | --- |
| **UINT8** | `uint8_t` | Unsigned 8-bit integer |
| **BYTE** | `uint8_t` | Unsigned 8-bit integer |
| **UINT16** | `uint16_t` | Unsigned 16-bit integer |
| **UINT32** | `uint32_t` | Unsigned 32-bit integer |
| **UINT64** | `uint64_t` | Unsigned 64-bit integer |
| **BOOL** | `int` | Boolean (TRUE=1, FALSE=0) |
| **TPM_HANDLE** | `UINT32` | 32-bit handle |

### 6.2 Algorithm Identifiers (TPM_ALG_ID)

| Name | Value | Description |
| --- | --- | --- |
| **TPM_ALG_RSA** | `0x0001` | RSA algorithm |
| **TPM_ALG_SHA256** | `0x000B` | SHA-256 hash |
| **TPM_ALG_NULL** | `0x0010` | Null algorithm |
| **TPM_ALG_RSASSA** | `0x0014` | RSA signature (PKCS1 v1.5) |
| **TPM_ALG_RSAPSS** | `0x0016` | RSA signature (PSS) |
| **TPM_ALG_OAEP** | `0x0017` | RSA encryption (OAEP) |

### 6.3 Response Codes (TPM_RC)

| Name | Value | Description |
| --- | --- | --- |
| **TPM_RC_SUCCESS** | `0x000` | Command successful |
| **TPM_RC_INITIALIZE** | `0x100` | TPM not initialized |
| **TPM_RC_FAILURE** | `0x101` | TPM failure mode |
| **TPM_RC_VALUE** | `0x084` | Value out of range |
| **TPM_RC_HIERARCHY** | `0x085` | Hierarchy not enabled |
| **TPM_RC_HANDLE** | `0x08B` | Incorrect handle |

### 6.4 Structure Tags (TPM_ST)

| Name | Value | Description |
| --- | --- | --- |
| **TPM_ST_NO_SESSIONS** | `0x8001` | No sessions |
| **TPM_ST_SESSIONS** | `0x8002` | Sessions |
| **TPM_ST_CREATION** | `0x8021` | Creation ticket |
| **TPM_ST_HASHCHECK** | `0x8024` | Hashcheck ticket |

### 6.5 Handles

- **TPM_RH_OWNER** (`0x40000001`)
- **TPM_RH_PLATFORM** (`0x4000000C`)
- **TPM_RH_ENDORSEMENT** (`0x4000000B`)
- **TPM_RH_NULL** (`0x40000007`)

Transient object range: `0x80000000` to `0x80FFFFFF`.

### 6.6 TPMA_OBJECT (Selected Bits)

| Bit | Name | Description |
| --- | --- | --- |
| 1 | **fixedTPM** | Object hierarchy cannot change |
| 2 | **stClear** | Saved context invalid after reset |
| 4 | **fixedParent** | Parent cannot change |
| 5 | **sensitiveDataOrigin** | Sensitive data generated by TPM |
| 6 | **userWithAuth** | HMAC/password auth allowed |
| 10 | **noDA** | Not subject to dictionary attack |
| 16 | **restricted** | Key usage restricted |
| 17 | **decrypt** | Private key used to decrypt |
| 18 | **sign / encrypt** | Private key used to sign |

### 6.7 Sized Buffers (Examples)

- **TPM2B_DIGEST:** `size`, `buffer`
- **TPM2B_NAME:** `size`, `name`
- **TPM2B_DATA:** `size`, `buffer`
- **TPM2B_PUBLIC:** `size`, `publicArea`
- **TPM2B_PRIVATE:** `size`, `buffer`
- **TPM2B_SENSITIVE_CREATE:** `size`, `sensitive`

### 6.8 Key and Object Structures (Selected)

- **TPMT_PUBLIC:** public area (type, nameAlg, attributes, policy, parameters, unique)
- **TPMS_SENSITIVE_CREATE:** userAuth and sensitive data
- **TPMT_SIG_SCHEME:** signature scheme
- **TPMT_SIGNATURE:** signature output
- **TPMS_CREATION_DATA:** creation metadata (PCR, locality, parent info, outsideInfo)

### 6.9 Unions (Selected)

- **TPMU_PUBLIC_PARMS:** `rsaDetail`, `symDetail`, `keyedHashDetail`
- **TPMU_PUBLIC_ID:** `rsa`, `keyedHash`
- **TPMU_SIGNATURE:** `rsassa`, `rsapss`, `hmac`

---

## 7. Operational State Machine

### 7.1 States

- **Power-Off:** No power or reset asserted.
- **Initialization:** Waits for startup command; returns `TPM_RC_INITIALIZE` on unexpected commands.
- **Startup:** Executes clear or state-based initialization.
- **Operational:** Normal command processing.
- **Failure Mode:** `TPM_RC_FAILURE` for most commands; reset required to exit.
- **Field Upgrade Mode (FUM):** Firmware update path.

### 7.2 Startup and Shutdown Types

- **TPM_SU (Type: `UINT16`)**
  - `TPM_SU_CLEAR` (0x0000): Clear or restart path.
  - `TPM_SU_STATE` (0x0001): Resume path.

### 7.3 State Attribute Structures (via TPM2_GetCapability)

- **TPMA_STARTUP_CLEAR (Type: `UINT32`)**
  - `phEnable`, `shEnable`, `ehEnable`, `readOnly`, `orderly`
- **TPMA_PERMANENT (Type: `UINT32`)**
  - `disableClear`, `inLockout`
- **TPMA_MODES (Type: `UINT32`)**
  - `FIPS_140_2`

### 7.4 Property Tags

- **TPM_PT_PERMANENT** (PT_VAR + 0)
- **TPM_PT_STARTUP_CLEAR** (PT_VAR + 1)
- **TPM_PT_MODES** (PT_FIXED + 45)

### 7.5 State-Specific Response Codes

- `TPM_RC_INITIALIZE` (0x100)
- `TPM_RC_FAILURE` (0x101)
- `TPM_RC_UPGRADE` (0x12D)
- `TPM_RC_REBOOT` (0x130)
- `TPM_RC_READ_ONLY` (0x156)
- `TPM_RC_NV_UNINITIALIZED` (0x14A)

### 7.6 Helper Types and Command Codes

- **TPMI_YES_NO (Type: `BYTE`)**: `NO` (0), `YES` (1)
- **TPM_CC (Type: `UINT32`)**:
  - `TPM_CC_Startup` (0x00000144)
  - `TPM_CC_Shutdown` (0x00000145)
  - `TPM_CC_SelfTest` (0x00000143)
  - `TPM_CC_GetTestResult` (0x0000017C)
  - `TPM_CC_GetCapability` (0x0000017A)
  - `TPM_CC_FieldUpgradeStart` (0x0000012F)
  - `TPM_CC_FieldUpgradeData` (0x00000141)

---

## 8. Deliverables

- **Modified QEMU Source Code** with S32K358 TPM peripheral integration.
- **Verification Firmware** demonstrating `CreatePrimary -> Create -> Load -> Sign`.
- **Design Documentation** covering simulation logic and host/guest interaction.

---

## 9. Potential Future Expansions

1. PCR support (measured boot)
2. NV storage persistence
3. Attestation (e.g., `TPM2_Quote`)

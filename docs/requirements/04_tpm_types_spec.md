# TPM 2.0 Types Specification

This document defines the data types, structures, constants, and unions required to implement the subset of TPM 2.0 commands specified.

## 1. Base Types & Primitive Types

These are the fundamental types used throughout the specification.

| Type Name | Base Type | Description |
| --- | --- | --- |
| **UINT8** | `uint8_t` | Unsigned 8-bit integer |
| **BYTE** | `uint8_t` | Unsigned 8-bit integer |
| **UINT16** | `uint16_t` | Unsigned 16-bit integer |
| **UINT32** | `uint32_t` | Unsigned 32-bit integer |
| **UINT64** | `uint64_t` | Unsigned 64-bit integer |
| **BOOL** | `int` | A bit in an integer (TRUE=1, FALSE=0) |
| **TPM_HANDLE** | `UINT32` | 32-bit handle referencing a shielded location |

---

## 2. Constants

### 2.1 Algorithm Identifiers (TPM_ALG_ID)

Used to identify algorithms for keys, hashes, and signatures.

| Name | Value | Description |
| --- | --- | --- |
| **TPM_ALG_RSA** | `0x0001` | RSA algorithm |
| **TPM_ALG_SHA256** | `0x000B` | SHA-256 Hash |
| **TPM_ALG_NULL** | `0x0010` | Null algorithm |
| **TPM_ALG_RSASSA** | `0x0014` | RSA Signature (PKCS1 v1.5) |
| **TPM_ALG_RSAPSS** | `0x0016` | RSA Signature (PSS) |
| **TPM_ALG_OAEP** | `0x0017` | RSA Encryption (OAEP) |

### 2.2 Response Codes (TPM_RC)

Return values indicating success or specific failure modes.

| Name | Value | Description |
| --- | --- | --- |
| **TPM_RC_SUCCESS** | `0x000` | Command successful |
| **TPM_RC_INITIALIZE** | `0x100` | TPM not initialized |
| **TPM_RC_FAILURE** | `0x101` | Commands not accepted due to failure |
| **TPM_RC_VALUE** | `0x084` | Value is out of range (Format 1) |
| **TPM_RC_HIERARCHY** | `0x085` | Hierarchy not enabled |
| **TPM_RC_HANDLE** | `0x08B` | Handle is not correct for use |

### 2.3 Structure Tags (TPM_ST)

Used to disambiguate structure types in command/response headers.

| Name | Value | Description |
| --- | --- | --- |
| **TPM_ST_NO_SESSIONS** | `0x8001` | Command/Response with no sessions |
| **TPM_ST_SESSIONS** | `0x8002` | Command/Response with sessions |
| **TPM_ST_CREATION** | `0x8021` | Tag for Creation Ticket |
| **TPM_ST_HASHCHECK** | `0x8024` | Tag for Hashcheck Ticket |

---

## 3. Handles & Interface Types

### 3.1 Hierarchy Handles (TPMI_RH_HIERARCHY)

Handles used as inputs for `TPM2_CreatePrimary`.

- **TPM_RH_OWNER** (`0x40000001`): Storage hierarchy
- **TPM_RH_PLATFORM** (`0x4000000C`): Platform hierarchy
- **TPM_RH_ENDORSEMENT** (`0x4000000B`): Endorsement hierarchy
- **TPM_RH_NULL** (`0x40000007`): Null hierarchy

### 3.2 Object Handles (TPMI_DH_OBJECT)

References to loaded objects (transient or persistent).

- **Transient Range**: `0x80000000` to `0x80FFFFFF`
- **Persistent Range**: `0x81000000` to `0x81FFFFFF`

---

## 4. Attribute Structures

### 4.1 TPMA_OBJECT

Bit field indicating an object's use and authorization.

| Bit | Name | Description |
| --- | --- | --- |
| 1 | **fixedTPM** | Object hierarchy cannot change (non-duplicable) |
| 2 | **stClear** | Saved context invalid after TPM Reset |
| 4 | **fixedParent** | Parent cannot change (non-duplicable) |
| 5 | **sensitiveDataOrigin** | TPM generated the sensitive data |
| 6 | **userWithAuth** | Authorization via HMAC/Password allowed |
| 10 | **noDA** | Not subject to dictionary attack protection |
| 16 | **restricted** | Key usage restricted to specific formats |
| 17 | **decrypt** | Private key used to decrypt |
| 18 | **sign / encrypt** | Private key used to sign |

---

## 5. Sized Buffers

Structures containing a size field followed by a data buffer.

### 5.1 TPM2B_DIGEST

Used for hashes and digests.

- **size** (`UINT16`): Size in octets of the buffer.
- **buffer** (`BYTE[]`): The digest data (max size depends on hash alg).

### 5.2 TPM2B_NAME

Used for Object Names.

- **size** (`UINT16`): Size of the name.
- **name** (`BYTE[]`): The Name structure (typically AlgID + Digest).

### 5.3 TPM2B_DATA

Used for `outsideInfo` in creation commands.

- **size** (`UINT16`): Size in octets.
- **buffer** (`BYTE[]`): Data buffer.

### 5.4 TPM2B_PUBLIC

Used to pass public area templates and return public keys.

- **size** (`UINT16`): Size of publicArea.
- **publicArea** (`TPMT_PUBLIC`): The public area structure.

### 5.5 TPM2B_PRIVATE

Used to store the encrypted sensitive area of an object.

- **size** (`UINT16`): Size of the private structure.
- **buffer** (`BYTE[]`): The encrypted private area.

### 5.6 TPM2B_SENSITIVE_CREATE

Input for `TPM2_Create` and `TPM2_CreatePrimary`.

- **size** (`UINT16`): Size of sensitive data.
- **sensitive** (`TPMS_SENSITIVE_CREATE`): Data to be sealed or auth values.

---

## 6. Key and Object Structures

### 6.1 TPMT_PUBLIC

Defines the public portion of an object.

| Type | Name | Description |
| --- | --- | --- |
| `TPMI_ALG_PUBLIC` | **type** | Algorithm/Object type (e.g., TPM_ALG_RSA). |
| `TPMI_ALG_HASH` | **nameAlg** | Hash alg used for the Name of the object. |
| `TPMA_OBJECT` | **objectAttributes** | Attributes (sign, decrypt, fixedTPM, etc.). |
| `TPM2B_DIGEST` | **authPolicy** | Optional policy digest. |
| `TPMU_PUBLIC_PARMS` | **parameters** | Type-specific parameters (Union). |
| `TPMU_PUBLIC_ID` | **unique** | Unique identifier (e.g., RSA Public Modulus). |

### 6.2 TPMS_SENSITIVE_CREATE

Contents of the sensitive area during creation.

| Type | Name | Description |
| --- | --- | --- |
| `TPM2B_AUTH` | **userAuth** | The initial authorization value (password). |
| `TPM2B_SENSITIVE_DATA` | **data** | Data to be sealed (empty for asymmetric keys). |

### 6.3 TPMT_SIG_SCHEME

Defines the signature scheme for `TPM2_Sign`.

| Type | Name | Description |
| --- | --- | --- |
| `TPMI_ALG_SIG_SCHEME` | **scheme** | Scheme selector (e.g., TPM_ALG_RSASSA). |
| `TPMU_SIG_SCHEME` | **details** | Scheme details (usually contains hash alg). |

### 6.4 TPMT_SIGNATURE

The output of a signing operation.

| Type | Name | Description |
| --- | --- | --- |
| `TPMI_ALG_SIG_SCHEME` | **sigAlg** | Selector of the algorithm used. |
| `TPMU_SIGNATURE` | **signature** | The signature data (Union). |

### 6.5 TPMS_CREATION_DATA

Data returned by creation commands linking the object to the TPM.

| Type | Name | Description |
| --- | --- | --- |
| `TPML_PCR_SELECTION` | **pcrSelect** | List of PCRs included in the digest. |
| `TPM2B_DIGEST` | **pcrDigest** | Digest of the selected PCRs. |
| `TPMA_LOCALITY` | **locality** | Locality at which object was created. |
| `TPM_ALG_ID` | **parentNameAlg** | Name alg of the parent. |
| `TPM2B_NAME` | **parentName** | Name of the parent. |
| `TPM2B_NAME` | **parentQualifiedName** | Qualified Name of the parent. |
| `TPM2B_DATA` | **outsideInfo** | Data provided by the caller. |

---

## 7. Tickets

Tickets provide proof that the TPM processed specific data.

### 7.1 TPMT_TK_CREATION

Ticket validating that an object was created by the TPM.

| Type | Name | Description |
| --- | --- | --- |
| `TPM_ST` | **tag** | Must be `TPM_ST_CREATION`. |
| `TPMI_RH_HIERARCHY` | **hierarchy** | Hierarchy associated with the Name. |
| `TPM2B_DIGEST` | **digest** | HMAC over the creation data. |

### 7.2 TPMT_TK_HASHCHECK

Ticket validating that a digest was created by the TPM (used in `TPM2_Sign`).

| Type | Name | Description |
| --- | --- | --- |
| `TPM_ST` | **tag** | Must be `TPM_ST_HASHCHECK`. |
| `TPMI_RH_HIERARCHY` | **hierarchy** | Hierarchy used to produce the ticket. |
| `TPM2B_DIGEST` | **digest** | HMAC over the digest. |

---

## 8. Lists

### 8.1 TPML_PCR_SELECTION

List used to select PCRs.

| Type | Name | Description |
| --- | --- | --- |
| `UINT32` | **count** | Number of selection structures. |
| `TPMS_PCR_SELECTION[]` | **pcrSelections** | Array of PCR selections. |

---

## 9. Unions

Unions allow structures to contain different data types based on a selector.

### 9.1 TPMU_PUBLIC_PARMS

Union of algorithm parameters for `TPMT_PUBLIC`.

- **Selector**: `type` (`TPMI_ALG_PUBLIC`)
- **Fields**:
  - `rsaDetail` (`TPMS_RSA_PARMS`) used when selector is `TPM_ALG_RSA`.
  - `symDetail` (`TPMS_SYMCIPHER_PARMS`) used when selector is `TPM_ALG_SYMCIPHER`.
  - `keyedHashDetail` (`TPMS_KEYEDHASH_PARMS`) used when selector is `TPM_ALG_KEYEDHASH`.

### 9.2 TPMU_PUBLIC_ID

Union of unique identifiers for `TPMT_PUBLIC`.

- **Selector**: `type` (`TPMI_ALG_PUBLIC`)
- **Fields**:
  - `rsa` (`TPM2B_PUBLIC_KEY_RSA`) used when selector is `TPM_ALG_RSA`.
  - `keyedHash` (`TPM2B_DIGEST`) used when selector is `TPM_ALG_KEYEDHASH`.

### 9.3 TPMU_SIGNATURE

Union of signature data.

- **Selector**: `sigAlg` (`TPMI_ALG_SIG_SCHEME`)
- **Fields**:
  - `rsassa` (`TPMS_SIGNATURE_RSA`) used when selector is `TPM_ALG_RSASSA`.
  - `rsapss` (`TPMS_SIGNATURE_RSA`) used when selector is `TPM_ALG_RSAPSS`.
  - `hmac` (`TPMT_HA`) used when selector is `TPM_ALG_HMAC`.

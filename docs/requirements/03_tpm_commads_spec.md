# TPM 2.0 Commands Specification

## Command Reference Documentation

### 1. General Command Processing

To support the "Command Validation" requirement (Section 2.2 of your spec), the simulation must validate the command header before execution.

- **Header Validation:** The TPM must successfully unmarshal a `TPMI_ST_COMMAND_TAG` (checking for `TPM_ST_SESSIONS` or `TPM_ST_NO_SESSIONS`) and a `UINT32` command size.
- **Command Code:** The system must verify that the command code (`TPM_CC`) is implemented.
- **Initialization:** Generally, if the TPM has not been initialized via `TPM2_Startup`, it should return `TPM_RC_INITIALIZE` for most commands.

---

### 2. Hierarchy Provisioning: `TPM2_CreatePrimary`

This function is required to establish the root of trust (the Primary Object) from which all other keys are derived.

- **Description:** This command creates a Primary Object under one of the Primary Seeds (e.g., Storage, Endorsement, or Platform). It uses a `TPM2B_PUBLIC` template to define the object's properties.
- **Key Derivation:** The TPM derives the object from the Primary Seed indicated by the `primaryHandle` using an approved Key Derivation Function (KDF). If called multiple times with the same template and seed, it produces the same Primary Object.
- **Outputs:** The command creates and loads the object but **does not** return the sensitive (private) area. This prevents the key from being reloaded later; it must be recreated or made persistent.

#### Command Interface (Table 174)

| Type | Name | Description |
| --- | --- | --- |
| `TPMI_RH_HIERARCHY` | `primaryHandle` | Handle of the hierarchy (e.g., `TPM_RH_OWNER`). |
| `TPM2B_SENSITIVE_CREATE` | `inSensitive` | The sensitive data (e.g., user auth). |
| `TPM2B_PUBLIC` | `inPublic` | The public template defining key attributes. |
| `TPM2B_DATA` | `outsideInfo` | Data included in creation data for linkage. |
| `TPML_PCR_SELECTION` | `creationPCR` | PCRs to include in creation data. |

#### Response Interface (Table 175)

| Type | Name | Description |
| --- | --- | --- |
| `TPM_HANDLE` | `objectHandle` | Handle for the loaded Primary Object. |
| `TPM2B_PUBLIC` | `outPublic` | The public portion of the created object. |
| `TPM2B_CREATION_DATA` | `creationData` | Data linking the object to the TPM. |
| `TPM2B_DIGEST` | `creationHash` | Digest of the creation data. |
| `TPMT_TK_CREATION` | `creationTicket` | Ticket used to validate creation data. |
| `TPM2B_NAME` | `name` | The Name of the created object. |

---

### 3. Object Creation: `TPM2_Create`

This command generates the RSA Key Pairs (child objects) that will be used for signing.

- **Description:** Creates an object that can be loaded later using `TPM2_Load`. Unlike `CreatePrimary`, this returns the encrypted private portion of the key.
- **Creation Data:** The TPM returns the object's creation data, its public area (`outPublic`), and its encrypted sensitive area (`outPrivate`).
- **Validation:** The TPM validates the attributes in the `inPublic` template. If the object is an asymmetric key (like RSA), the private key is TPM-generated.
- **Encryption:** The sensitive area is encrypted using the symmetric key of the parent object.

#### Command Interface (Table 18)

| Type | Name | Description |
| --- | --- | --- |
| `TPMI_DH_OBJECT` | `parentHandle` | Handle of the parent key (must be loaded). |
| `TPM2B_SENSITIVE_CREATE` | `inSensitive` | Initial sensitive data (e.g., auth value). |
| `TPM2B_PUBLIC` | `inPublic` | Public template for the new key. |
| `TPM2B_DATA` | `outsideInfo` | Data for creation linkage. |
| `TPML_PCR_SELECTION` | `creationPCR` | PCR selection for creation data. |

#### Response Interface (Table 19)

| Type | Name | Description |
| --- | --- | --- |
| `TPM2B_PRIVATE` | `outPrivate` | The private portion (encrypted). |
| `TPM2B_PUBLIC` | `outPublic` | The public portion of the created object. |
| `TPM2B_CREATION_DATA` | `creationData` | Creation data structure. |
| `TPM2B_DIGEST` | `creationHash` | Digest of creation data. |
| `TPMT_TK_CREATION` | `creationTicket` | Validation ticket. |

---

### 4. Context Management: `TPM2_Load`

This command moves the keys created by `TPM2_Create` into the simulation's volatile memory.

- **Description:** Used to load objects (both public and private portions) into the TPM.
- **Integrity Check:** The integrity value of the private blob must be checked *before* the private area is decrypted or unmarshaled to prevent attacks.
- **Binding:** The TPM validates that the public and sensitive portions are cryptographically linked.
- **Naming:** The command returns the "Name" of the object, which is the digest of the public area (used for authorization and identification).

#### Command Interface (Table 20)

| Type | Name | Description |
| --- | --- | --- |
| `TPMI_DH_OBJECT` | `parentHandle` | Handle of the parent key. |
| `TPM2B_PRIVATE` | `inPrivate` | The private portion of the object. |
| `TPM2B_PUBLIC` | `inPublic` | The public portion of the object. |

#### Response Interface (Table 21)

| Type | Name | Description |
| --- | --- | --- |
| `TPM_HANDLE` | `objectHandle` | Handle (transient) for the loaded object. |
| `TPM2B_NAME` | `name` | Name of the loaded object. |

---

### 5. Cryptographic Operations: `TPM2_Sign`

This command demonstrates the utility of the keys by performing a cryptographic signature.

- **Description:** Signs an externally provided hash (digest) using a specific symmetric or asymmetric signing key.
- **Constraints:** The key referenced by `keyHandle` must have the `sign` attribute SET.
- **Scheme Validation:** If the key has a default scheme (e.g., RSASSA), the input scheme must match it or be `TPM_ALG_NULL`. If the key is restricted, validation tickets may be required.

#### Command Interface (Table 109)

| Type | Name | Description |
| --- | --- | --- |
| `TPMI_DH_OBJECT` | `keyHandle` | Handle of the key to perform signing. |
| `TPM2B_DIGEST` | `digest` | The digest to be signed. |
| `TPMT_SIG_SCHEME` | `inScheme` | Signing scheme to use. |
| `TPMT_TK_HASHCHECK` | `validation` | Proof that the digest was created by the TPM (optional for unrestricted keys). |

#### Response Interface (Table 110)

| Type | Name | Description |
| --- | --- | --- |
| `TPMT_SIGNATURE` | `signature` | The resulting signature structure. |

---

### 6. Verification: `TPM2_ReadPublic`

This command is required to retrieve the public key data to verify the signature externally.

- **Description:** Allows access to the public area of a loaded object.
- **Authorization:** Reading the public area does **not** require authorization.
- **Output:** Returns the public area (`TPM2B_PUBLIC`), the Name, and the Qualified Name of the object.

#### Command Interface (Table 24)

| Type | Name | Description |
| --- | --- | --- |
| `TPMI_DH_OBJECT` | `objectHandle` | TPM handle of the object to read. |

#### Response Interface (Table 25)

| Type | Name | Description |
| --- | --- | --- |
| `TPM2B_PUBLIC` | `outPublic` | Structure containing the public area. |
| `TPM2B_NAME` | `name` | Name of the object. |
| `TPM2B_NAME` | `qualifiedName` | Qualified Name of the object. |

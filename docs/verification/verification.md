# Verification Properties for TPM 2.0 Simulation (S32K358)

This document lists the properties a verification firmware should test to assess correct TPM behavior
per the project specification. The focus is on the supported command subset, command validation,
state machine behavior, and cryptographic/key lifecycle behavior.

## 1. Transport and Command Framing

- **FIFO byte-stream transport**: Command bytes are accepted in order and responses are produced
  after full command receipt.
- **Command header size handling**: The `commandSize` field is honored; extra bytes are ignored or
  cause an error, and short buffers are rejected.
- **Tag validation**: Only `TPM_ST_NO_SESSIONS` and `TPM_ST_SESSIONS` are accepted; any other tag
  returns an error response.
- **Command code validation**: Unimplemented `TPM_CC` values return an error response.
- **Native endianness**: Multi-byte fields are interpreted in native endianness (no TCG BE swap).

## 2. State Machine and Initialization

- **Power-off to init gate**: Before `TPM2_Startup`, all normal commands return `TPM_RC_INITIALIZE`.
- **Startup(CLEAR)**: After `TPM2_Startup(TPM_SU_CLEAR)`, TPM enters operational state and accepts
  the required command set.
- **Startup(STATE)**: If used without prior `Shutdown(STATE)`, returns `TPM_RC_NV_UNINITIALIZED` or
  fails as specified by the state model.
- **Failure mode behavior**: If a failure mode is triggered (e.g., self-test failure), normal
  commands return `TPM_RC_FAILURE` until reset.
- **Field upgrade mode isolation**: When entering FUM, only field-upgrade commands are accepted;
  others return `TPM_RC_UPGRADE`.
- **Reset exits special modes**: `_TPM_Init` (reset) returns the device to Initialization state.

## 3. CreatePrimary (Hierarchy Provisioning)

- **Hierarchy handle validation**: Accepts `TPM_RH_OWNER`, `TPM_RH_PLATFORM`,
  `TPM_RH_ENDORSEMENT`, `TPM_RH_NULL`; rejects others with `TPM_RC_HIERARCHY` or `TPM_RC_HANDLE`.
- **Public template parsing**: `TPM2B_PUBLIC` is parsed and validated; malformed sizes or types
  return `TPM_RC_VALUE`.
- **Key generation**: Produces a primary RSA key pair internally (no external libraries).
- **Loaded object**: Returns a transient `objectHandle` in `0x80000000`..`0x80FFFFFF`.
- **Public area**: Returned `outPublic` matches the template attributes and key parameters.
- **Name calculation**: Returned `name` matches the hash of the public area using `nameAlg`.

## 4. Create (Child Object Generation)

- **Parent handle required**: `parentHandle` must reference a currently loaded object.
- **Template validation**: `inPublic` attributes for RSA signing key are validated (e.g., `sign` set,
  unsupported combinations rejected).
- **Sensitive create parsing**: `TPM2B_SENSITIVE_CREATE` is parsed and its size validated.
- **OutPrivate produced**: `outPrivate` is returned and non-empty for asymmetric keys.
- **OutPublic produced**: `outPublic` corresponds to the generated key pair.
- **Creation data and hash**: `creationData` and `creationHash` are returned and internally
  consistent (hash of creation data).

## 5. Load (Context Management)

- **Private/public binding**: `inPrivate` and `inPublic` must be linked; mismatched pairs fail.
- **Integrity check**: Private blob integrity is validated before use; invalid blobs fail.
- **Loaded handle**: Returns a transient `objectHandle` and a valid `name` for the object.

## 6. Sign (Cryptographic Operation)

- **Key handle validity**: `keyHandle` must reference a loaded signing key.
- **Attribute enforcement**: Key must have `sign` attribute; otherwise return an error.
- **Scheme handling**: Accepts `TPM_ALG_RSASSA` and `TPM_ALG_RSAPSS` as implemented; rejects
  unsupported schemes.
- **Digest handling**: Correctly signs the provided `digest` and returns a valid signature.
- **Signature verification**: The signature verifies against the public key from `ReadPublic`.

## 7. ReadPublic (Public Data)

- **Handle validation**: `objectHandle` must reference a loaded object.
- **No auth required**: Succeeds without authorization/session.
- **Public area consistency**: Returned `outPublic`, `name`, and `qualifiedName` are consistent with
  the loaded object and with `Create`/`CreatePrimary` outputs.

## 8. Command Workflow Integration

- **End-to-end path**: `CreatePrimary -> Create -> Load -> Sign` completes without errors.
- **Reuse protection**: Attempting to `Load` with a stale or modified `outPrivate` fails.
- **Multiple objects**: Multiple child keys under one primary can be created, loaded, and used.

## 9. Error Handling and Response Codes

- **Initialize error**: Returns `TPM_RC_INITIALIZE` when not started.
- **Handle error**: Returns `TPM_RC_HANDLE` for invalid or wrong-type handles.
- **Value error**: Returns `TPM_RC_VALUE` for malformed fields or unsupported sizes.
- **Failure error**: Returns `TPM_RC_FAILURE` for failure-mode commands.

## 10. Data Sizes and Boundaries

- **Sized buffers**: All `TPM2B_*` structures enforce size fields; oversized inputs fail.
- **Digest size**: `TPM2B_DIGEST` size matches the hash algorithm used (e.g., SHA-256).
- **Public key size**: RSA key size matches the template and returns expected modulus size.

## 11. Native Endianness Checks

- **Multi-byte parsing**: Validate that a command encoded in host endianness is accepted and that
  BE-encoded fields are rejected or misinterpreted (to confirm native-endian behavior).

## 12. Non-Goals (Should Not Be Required)

- **PCR operations**: Not implemented; any PCR-related commands should fail.
- **NV storage**: Not implemented; NV commands should fail.
- **Attestation commands**: Not implemented; `TPM2_Quote` and similar should fail.

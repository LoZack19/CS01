# TPM Spec Compliance State (S32K358)

Legend:

- Completed and compliant
- Completed but non-compliant
- Missing

## 1. Project Objective

- Design and implement a TPM 2.0 simulation within QEMU for S32K358 — Completed and compliant. The device model and command dispatch are implemented in [qemu/hw/misc/s32k358_tpm.c](qemu/hw/misc/s32k358_tpm.c) and [qemu/hw/misc/tpm_cmds.c](qemu/hw/misc/tpm_cmds.c).
- Functional command-response chain and robust cryptographic key management module — Completed but non-compliant. Command flow exists, but key usage is simplified (e.g., Sign uses a fixed key and ignores loaded object handles) in [qemu/hw/misc/tpm_cmds.c](qemu/hw/misc/tpm_cmds.c).

## 2. Functional Scope

- Security co-processor simulation interface for crypto without exposing private key material — Completed but non-compliant. Private data blobs are copied raw in [qemu/hw/misc/tpm_load.c](qemu/hw/misc/tpm_load.c), which exposes sensitive material in the command response path.

### 2.1 Supported TPM Command Suite

- TPM2_CreatePrimary — Completed and compliant. Implemented in [qemu/hw/misc/tpm_cmds.c](qemu/hw/misc/tpm_cmds.c) and dispatched in [qemu/hw/misc/s32k358_tpm.c](qemu/hw/misc/s32k358_tpm.c).
- TPM2_Create — Completed and compliant. Implemented in [qemu/hw/misc/tpm_cmds.c](qemu/hw/misc/tpm_cmds.c) and dispatched in [qemu/hw/misc/s32k358_tpm.c](qemu/hw/misc/s32k358_tpm.c).
- TPM2_Load — Completed and compliant. Implemented in [qemu/hw/misc/tpm_load.c](qemu/hw/misc/tpm_load.c) and dispatched in [qemu/hw/misc/s32k358_tpm.c](qemu/hw/misc/s32k358_tpm.c).
- TPM2_Sign — Completed but non-compliant. Uses a fixed key and does not use the loaded object identified by `keyHandle` in [qemu/hw/misc/tpm_cmds.c](qemu/hw/misc/tpm_cmds.c).
- TPM2_ReadPublic — Missing. No handler or dispatch case exists in [qemu/hw/misc/s32k358_tpm.c](qemu/hw/misc/s32k358_tpm.c) or [qemu/hw/misc/tpm_cmds.c](qemu/hw/misc/tpm_cmds.c).

### 2.2 Data Integrity and Format

- Native endianness processing — Completed and compliant. FIFO marshal/unmarshal uses raw byte copies in [qemu/hw/misc/tpm_marshal.c](qemu/hw/misc/tpm_marshal.c).
- Command validation (tags and sizes) — Completed but non-compliant. Tag checks exist, and most commands validate sizes, but `TPM2_CreatePrimary` does not verify its input size in [qemu/hw/misc/s32k358_tpm.c](qemu/hw/misc/s32k358_tpm.c).

## 3. Technical Architecture

### 3.1 Simulation Interface Layer

- MMIO interface on S32K358 system bus — Completed and compliant in [qemu/hw/misc/s32k358_tpm.c](qemu/hw/misc/s32k358_tpm.c).
- FIFO-based command transport — Completed and compliant using `Fifo8` in [qemu/hw/misc/s32k358_tpm.c](qemu/hw/misc/s32k358_tpm.c).
- State machine (Idle, Receiving, Executing, Completion) — Completed and compliant with simplified states in [qemu/hw/misc/s32k358_tpm.c](qemu/hw/misc/s32k358_tpm.c).

### 3.2 Cryptographic Module

- Internal cryptographic implementation — Completed and compliant in [qemu/hw/misc/tpm_crypt.c](qemu/hw/misc/tpm_crypt.c) with no external crypto libraries.
- Key storage simulation (volatile loaded vs saved objects) — Completed and compliant with transient object slots in [qemu/hw/misc/tpm_object.c](qemu/hw/misc/tpm_object.c) and load logic in [qemu/hw/misc/tpm_load.c](qemu/hw/misc/tpm_load.c).
- Lifecycle management (generation, usage, eviction of handles) — Completed but non-compliant. Generation and loading exist, but there is no eviction/flush command path in [qemu/hw/misc/tpm_cmds.c](qemu/hw/misc/tpm_cmds.c).

## 4. Requirements

### 4.1 Core TPM Command Workflow

- CreatePrimary -> Create -> Load -> Sign — Completed but non-compliant. The sequence exists as separate commands, but Sign does not use the loaded object and firmware tests do not chain the handle into Sign. See [qemu/hw/misc/tpm_cmds.c](qemu/hw/misc/tpm_cmds.c) and [firmware/src/main.c](firmware/src/main.c).

### 4.2 Internal Functional Requirements

- MMIO interface logic — Completed and compliant in [qemu/hw/misc/s32k358_tpm.c](qemu/hw/misc/s32k358_tpm.c).
- Command/tag validation — Completed but non-compliant; size checks are not consistent across all commands in [qemu/hw/misc/s32k358_tpm.c](qemu/hw/misc/s32k358_tpm.c).
- Native endianness processing — Completed and compliant in [qemu/hw/misc/tpm_marshal.c](qemu/hw/misc/tpm_marshal.c).
- Internal RSA backend — Completed but non-compliant. RSA operations are simplified and not a real RSA implementation in [qemu/hw/misc/tpm_crypt.c](qemu/hw/misc/tpm_crypt.c).

### 4.3 Explicitly Excluded Functions (Current Phase)

- PCR support — Completed and compliant (explicitly excluded and not implemented).
- NV storage persistence — Completed and compliant (explicitly excluded; NV is in-memory only in [qemu/hw/misc/s32k358_tpm.c](qemu/hw/misc/s32k358_tpm.c)).
- Attestation commands (e.g., TPM2_Quote) — Completed and compliant (explicitly excluded and not implemented).

## 5. Command Reference (Subset)

### 5.1 General Command Processing

- Header validation (TPM_ST_SESSIONS or TPM_ST_NO_SESSIONS) — Completed and compliant in [qemu/hw/misc/s32k358_tpm.c](qemu/hw/misc/s32k358_tpm.c).
- Command code implemented check — Completed and compliant (unimplemented commands return `TPM_RC_COMMAND_CODE`) in [qemu/hw/misc/s32k358_tpm.c](qemu/hw/misc/s32k358_tpm.c).
- Initialization via TPM2_Startup required — Missing. There is no Startup command or initialization gate in [qemu/hw/misc/s32k358_tpm.c](qemu/hw/misc/s32k358_tpm.c).

### 5.2 TPM2_CreatePrimary

- Inputs/outputs implemented — Completed and compliant in [qemu/hw/misc/tpm_cmds.c](qemu/hw/misc/tpm_cmds.c).

### 5.3 TPM2_Create

- Inputs/outputs implemented — Completed and compliant in [qemu/hw/misc/tpm_cmds.c](qemu/hw/misc/tpm_cmds.c).

### 5.4 TPM2_Load

- Inputs/outputs implemented — Completed and compliant in [qemu/hw/misc/tpm_load.c](qemu/hw/misc/tpm_load.c).

### 5.5 TPM2_Sign

- Inputs/outputs implemented — Completed but non-compliant. Validation ticket is ignored and key material is not derived from the loaded object in [qemu/hw/misc/tpm_cmds.c](qemu/hw/misc/tpm_cmds.c).

### 5.6 TPM2_ReadPublic

- Inputs/outputs implemented — Missing. No implementation in [qemu/hw/misc/tpm_cmds.c](qemu/hw/misc/tpm_cmds.c).

## 6. Types, Constants, and Structures (Selected)

### 6.1 Base Types

- Defined — Completed and compliant in [qemu/include/hw/misc/tpm2_spec_protocol.h](qemu/include/hw/misc/tpm2_spec_protocol.h).

### 6.2 Algorithm Identifiers (TPM_ALG_ID)

- Defined — Completed and compliant in [qemu/include/hw/misc/tpm2_spec_protocol.h](qemu/include/hw/misc/tpm2_spec_protocol.h).

### 6.3 Response Codes (TPM_RC)

- Defined — Completed but non-compliant. `TPM_RC_INITIALIZE` is missing in [qemu/include/hw/misc/tpm2_spec_protocol.h](qemu/include/hw/misc/tpm2_spec_protocol.h).

### 6.4 Structure Tags (TPM_ST)

- Defined — Completed but non-compliant. `TPM_ST_HASHCHECK` is missing in [qemu/include/hw/misc/tpm2_spec_protocol.h](qemu/include/hw/misc/tpm2_spec_protocol.h).

### 6.5 Handles

- Defined — Completed and compliant in [qemu/include/hw/misc/tpm2_spec_protocol.h](qemu/include/hw/misc/tpm2_spec_protocol.h).

### 6.6 TPMA_OBJECT (Selected Bits)

- Defined — Completed and compliant in [qemu/include/hw/misc/tpm2_spec_protocol.h](qemu/include/hw/misc/tpm2_spec_protocol.h).

### 6.7 Sized Buffers

- Defined — Completed and compliant in [qemu/include/hw/misc/tpm2_spec_protocol.h](qemu/include/hw/misc/tpm2_spec_protocol.h).

### 6.8 Key and Object Structures

- Defined — Completed and compliant in [qemu/include/hw/misc/tpm2_spec_protocol.h](qemu/include/hw/misc/tpm2_spec_protocol.h).

### 6.9 Unions

- Defined — Completed and compliant in [qemu/include/hw/misc/tpm2_spec_protocol.h](qemu/include/hw/misc/tpm2_spec_protocol.h).

## 7. Operational State Machine

### 7.1 States

- Power-Off / Initialization / Startup / Failure Mode / FUM — Missing. The device uses a simplified state machine without these TPM states in [qemu/hw/misc/s32k358_tpm.c](qemu/hw/misc/s32k358_tpm.c).
- Operational — Completed but non-compliant. There is operational command handling, but it is not gated by Startup or failure modes in [qemu/hw/misc/s32k358_tpm.c](qemu/hw/misc/s32k358_tpm.c).

### 7.2 Startup and Shutdown Types (TPM_SU)

- Defined/handled — Missing. No constants or command handling in [qemu/include/hw/misc/tpm2_spec_protocol.h](qemu/include/hw/misc/tpm2_spec_protocol.h) or [qemu/hw/misc/s32k358_tpm.c](qemu/hw/misc/s32k358_tpm.c).

### 7.3 State Attribute Structures (TPM2_GetCapability)

- Defined/handled — Missing. No GetCapability implementation or structures in [qemu/hw/misc/s32k358_tpm.c](qemu/hw/misc/s32k358_tpm.c).

### 7.4 Property Tags

- Defined — Missing in [qemu/include/hw/misc/tpm2_spec_protocol.h](qemu/include/hw/misc/tpm2_spec_protocol.h).

### 7.5 State-Specific Response Codes

- Defined/used — Missing. Several codes (e.g., `TPM_RC_UPGRADE`, `TPM_RC_REBOOT`) are not defined or used in [qemu/include/hw/misc/tpm2_spec_protocol.h](qemu/include/hw/misc/tpm2_spec_protocol.h).

### 7.6 Helper Types and Command Codes

- TPMI_YES_NO — Missing in [qemu/include/hw/misc/tpm2_spec_protocol.h](qemu/include/hw/misc/tpm2_spec_protocol.h).
- TPM_CC_Startup/Shutdown/SelfTest/GetTestResult/GetCapability/FieldUpgrade* — Missing in [qemu/include/hw/misc/tpm2_spec_protocol.h](qemu/include/hw/misc/tpm2_spec_protocol.h) and unimplemented in [qemu/hw/misc/s32k358_tpm.c](qemu/hw/misc/s32k358_tpm.c).

## 8. Deliverables

- Modified QEMU source code with S32K358 TPM integration — Completed and compliant in [qemu/hw/misc/s32k358_tpm.c](qemu/hw/misc/s32k358_tpm.c).
- Verification firmware demonstrating CreatePrimary -> Create -> Load -> Sign — Completed but non-compliant. Firmware includes CreatePrimary/Create/Load tests and a Sign smoke test, but Sign is not chained to the loaded handle in [firmware/src/main.c](firmware/src/main.c) and enabled by [firmware/include/tpm_tests_config.h](firmware/include/tpm_tests_config.h).
- Design documentation covering simulation logic and host/guest interaction — Completed and compliant in [docs/project/structure.md](docs/project/structure.md) and [README.md](README.md).

## 9. Potential Future Expansions

- PCR support — Missing.
- NV storage persistence — Missing.
- Attestation (TPM2_Quote) — Missing.

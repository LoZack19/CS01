# Project structure and TPM internals (S32K358)

This document explains how the TPM model for the S32K358 board is wired into QEMU, which files implement each TPM function, and how the rest of the project is organized. It is meant as a quick, accurate map for new work.

## Top-level repository layout

- QEMU model and board code live in [qemu/](qemu/).
- Firmware and test code for the TPM peripheral live in [firmware/](firmware/).
- Requirements and specs live in [docs/requirements/](docs/requirements/).
- Project notes and this overview live in [docs/project/](docs/project/).
- Build and run instructions are in [README.md](README.md).

## How the TPM device is built in QEMU

The TPM model is compiled only when QEMU is configured with the S32K358 TPM device enabled. The build wiring is in [qemu/hw/misc/meson.build](qemu/hw/misc/meson.build) under the `CONFIG_S32K358_TPM` block. That list defines every C file that participates in the device.

## TPM device entry point and MMIO behavior

### Device model and MMIO

- The QEMU device implementation is in [qemu/hw/misc/s32k358_tpm.c](qemu/hw/misc/s32k358_tpm.c).
- It implements the memory-mapped register behavior, FIFO handling, state machine transitions, and command dispatch.

### Device state definition

- The device state struct, register layout, NV memory sizing, and reset defaults live in [qemu/include/hw/misc/s32k358_tpm.h](qemu/include/hw/misc/s32k358_tpm.h).

### What happens at runtime

1. Guest writes command bytes into the input FIFO via the TPM DATA FIFO MMIO register.
2. When the guest sets `TPM_STS.tpmGo`, the device unmarshals the command header and dispatches the command.
3. The command handler runs, marshals a response, and writes it into the output FIFO.
4. Guest reads the output FIFO until empty.

## Command dispatch and TPM command handlers

### Dispatcher

- The command dispatch table is inside the device model in [qemu/hw/misc/s32k358_tpm.c](qemu/hw/misc/s32k358_tpm.c). It parses the TPM command header, validates sizes, and calls the command implementation.

### Command implementations

- Command logic for supported TPM2 commands is in [qemu/hw/misc/tpm_cmds.c](qemu/hw/misc/tpm_cmds.c).
- Implemented commands include:
  - Random and hash: GetRandom, Hash
  - NV: NV_DefineSpace, NV_Write, NV_Read
  - Crypto: Sign, VerifySignature, RSA_Encrypt, RSA_Decrypt, EncryptDecrypt2
  - Key lifecycle: CreatePrimary, Create, Load

## Marshaling and protocol types

### Protocol definitions

- TPM 2.0 protocol structures, constants, and wire types are defined in [qemu/include/hw/misc/tpm2_spec_protocol.h](qemu/include/hw/misc/tpm2_spec_protocol.h).
- That header is the source for the generated firmware copy in [firmware/include/tpm2_spec_protocol.h](firmware/include/tpm2_spec_protocol.h).

### Wire-format marshaling

- FIFO marshaling helpers (`marshal`, `unmarshal`, and macros) are implemented in [qemu/hw/misc/tpm_marshal.c](qemu/hw/misc/tpm_marshal.c).
- TPM-specific canonical marshaling for `TPMT_PUBLIC` (used for Name computation) is implemented in [qemu/hw/misc/tpm_marshal_tpm.c](qemu/hw/misc/tpm_marshal_tpm.c).

## Authorization handling

- Password-session parsing for `TPM_ST_SESSIONS` commands is implemented in [qemu/hw/misc/tpm_auth.c](qemu/hw/misc/tpm_auth.c).
- This is intentionally simplified: it parses session data and accepts password sessions without full HMAC validation.

## NV storage and persistent state

- NV storage logic is implemented in [qemu/hw/misc/NvStorage.c](qemu/hw/misc/NvStorage.c).
- The device model allocates a fixed NV memory region, initializes it at realize-time, and hands it to the NV layer.
- NV functions support define, read, write, and index bookkeeping. It uses a simple linked-list style layout inside the fixed NV memory region.

## Crypto and deterministic primitives

- Core cryptographic helpers are in [qemu/hw/misc/tpm_crypt.c](qemu/hw/misc/tpm_crypt.c) with APIs declared in [qemu/hw/misc/tpm_crypt.h](qemu/hw/misc/tpm_crypt.h).
- Implementations include:
  - Random byte generation
  - SHA-256
  - Simplified RSA-PSS signing and verification
  - AES mode helpers for EncryptDecrypt2

## Object management, creation, and loading

The TPM object and hierarchy helpers are factored into small modules and gathered under the umbrella header [qemu/include/hw/misc/tpm_create_primary.h](qemu/include/hw/misc/tpm_create_primary.h). These are used by CreatePrimary, Create, and Load.

- **Utility helpers**: [qemu/hw/misc/tpm_util.c](qemu/hw/misc/tpm_util.c)
  - MemorySet, RcSafeAddToResult
- **Hierarchy helpers**: [qemu/hw/misc/tpm_hierarchy.c](qemu/hw/misc/tpm_hierarchy.c)
  - Hierarchy seeds, handle normalization, and hierarchy lookup
- **Object management**: [qemu/hw/misc/tpm_object.c](qemu/hw/misc/tpm_object.c)
  - Transient object slots, Name computation, creation checks, and creation data
- **Deterministic RNG**: [qemu/hw/misc/tpm_drbg.c](qemu/hw/misc/tpm_drbg.c)
  - DRBG for CreatePrimary and deterministic key material
- **Creation tickets**: [qemu/hw/misc/tpm_ticket.c](qemu/hw/misc/tpm_ticket.c)
  - HMAC-based creation ticket computation
- **Load support**: [qemu/hw/misc/tpm_load.c](qemu/hw/misc/tpm_load.c)
  - Private/public object loading and the TPM2_Load command

## End-to-end TPM flow (S32K358)

1. The S32K358 board exposes the TPM MMIO region in QEMU (device in [qemu/hw/misc/s32k358_tpm.c](qemu/hw/misc/s32k358_tpm.c)).
2. Firmware or guest software builds TPM command buffers using the protocol layout from [firmware/include/tpm2_spec_protocol.h](firmware/include/tpm2_spec_protocol.h).
3. The guest writes the command into the FIFO via MMIO and triggers execution with `TPM_STS.tpmGo`.
4. The TPM device unmarshals, dispatches, and executes the command using the command handlers in [qemu/hw/misc/tpm_cmds.c](qemu/hw/misc/tpm_cmds.c).
5. The response is marshaled into the output FIFO; the guest reads it out.

## Where to look first when changing behavior

- **New command**: add a handler in [qemu/hw/misc/tpm_cmds.c](qemu/hw/misc/tpm_cmds.c) and a dispatch case in [qemu/hw/misc/s32k358_tpm.c](qemu/hw/misc/s32k358_tpm.c).
- **Protocol types**: extend [qemu/include/hw/misc/tpm2_spec_protocol.h](qemu/include/hw/misc/tpm2_spec_protocol.h) and regenerate firmware headers if needed.
- **State machine / MMIO**: update [qemu/hw/misc/s32k358_tpm.c](qemu/hw/misc/s32k358_tpm.c) and the register definitions in [qemu/include/hw/misc/s32k358_tpm.h](qemu/include/hw/misc/s32k358_tpm.h).
- **Crypto or object internals**: check [qemu/hw/misc/tpm_crypt.c](qemu/hw/misc/tpm_crypt.c), [qemu/hw/misc/tpm_object.c](qemu/hw/misc/tpm_object.c), and [qemu/hw/misc/tpm_drbg.c](qemu/hw/misc/tpm_drbg.c).

## Notes on scope and intent

This TPM model is intentionally simplified and geared for education and experimentation. The code mirrors the TPM 2.0 spec structure while keeping cryptography and authorization minimal. Use it as a reference for the project’s current behavior, not as a production-quality TPM implementation.

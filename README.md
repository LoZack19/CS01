# TPM 2.0 Simulation Peripheral for S32K358 in QEMU

## 1. Introduction

This project implements a **Trusted Platform Module (TPM) 2.0** as a custom QEMU peripheral for the **NXP S32K358** automotive microcontroller. The TPM is emulated entirely in software — no external cryptographic libraries are used — and is accessible to guest firmware through a standard memory-mapped I/O (MMIO) interface.

The simulation covers the full key lifecycle mandated by the TCG 2.0 specification: hierarchy provisioning, child key generation, context loading, and cryptographic signing. Beyond the core workflow, it implements an operational state machine (Startup, Shutdown, Failure Mode, Field Upgrade Mode), self-contained cryptographic primitives (SHA-256, RSA, AES, DRBG), and a verification firmware that exercises and validates the TPM behavior from the guest side.

The project is developed as part of a cybersecurity curriculum and is designed for **education and experimentation**, not for production use. It mirrors the structure and naming conventions of the [ms-tpm-20-ref](https://github.com/microsoft/ms-tpm-20-ref) reference implementation while keeping the internals minimal and readable.

---

## 2. Project Specification and Requirements

### 2.1 Objective

The project objective, as defined in the [project specification](docs/requirements/01_project_specification.md), is to:

> Design and implement a generic TPM 2.0 simulation within QEMU, specifically tailored for the S32K358 platform. The implementation focuses on establishing a functional command-response chain and a robust cryptographic key management module.

The reference documentation is the [TCG TPM 2.0 Library Specification, Part 3 (Version 1.84)](https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-3-Version-184_pub.pdf).

### 2.2 Required Command Chain

The core deliverable is a working end-to-end command chain ([requirements](docs/requirements/02_requirements.md)):

```txt
TPM2_CreatePrimary  ->  TPM2_Create  ->  TPM2_Load  ->  TPM2_Sign
```

| Command | Role |
| --- | --- |
| `TPM2_CreatePrimary` | Establish the root of trust under a hierarchy seed |
| `TPM2_Create` | Generate an RSA child key pair under the primary |
| `TPM2_Load` | Load the child key into volatile memory for use |
| `TPM2_Sign` | Sign a digest using the loaded key |
| `TPM2_ReadPublic` | Retrieve the public key for external verification |

Full command input/output tables are in [03_tpm_commands_spec.md](docs/requirements/03_tpm_commads_spec.md) and the type system is in [04_tpm_types_spec.md](docs/requirements/04_tpm_types_spec.md).

### 2.3 Internal Requirements

| Requirement | Description |
| --- | --- |
| **MMIO Interface** | Data transfer via the S32K358 system bus |
| **Command Validation** | Header parsing, tag checking (`TPM_ST_SESSIONS` / `TPM_ST_NO_SESSIONS`), size validation |
| **Native Endianness** | All multi-byte fields in host byte order (no TCG Big-Endian swapping) |
| **Internal RSA Backend** | All cryptographic math implemented from scratch, no external libraries |

### 2.4 State Machine

The TPM operational state machine is specified in [05_tpm_state_machine_spec.md](docs/requirements/05_tpm_state_machine_spec.md) and requires six states:

```txt
Power-Off -> Initialization -> Startup -> Operational -> Shutdown -> Power-Off
                                  |                          |
                                  +-> Field Upgrade Mode     +-> Failure Mode
```

Commands must be gated by state: before `TPM2_Startup`, all normal commands return `TPM_RC_INITIALIZE`; in Failure Mode, only diagnostic commands are accepted; in Field Upgrade Mode, only upgrade commands pass through.

### 2.5 Explicitly Excluded (Current Phase)

- Platform Configuration Registers (PCRs)
- Non-volatile storage persistence across QEMU reboots
- Attestation commands (`TPM2_Quote`)

### 2.6 Deliverables

1. Modified QEMU source code with the S32K358 TPM peripheral
2. Verification firmware demonstrating the `CreatePrimary -> Create -> Load -> Sign` workflow
3. Design documentation covering simulation logic and firmware interaction

---

## 3. Project Structure

```txt
CS01/
├── qemu/                            # Modified QEMU with S32K358 TPM
│   ├── hw/misc/                     # TPM device model and command logic
│   │   ├── s32k358_tpm.c           # Main device: MMIO registers, FIFO, dispatch
│   │   ├── tpm_cmds.c              # Command handlers (crypto, NV, key lifecycle)
│   │   ├── tpm_state_machine.c     # Startup/Shutdown/SelfTest/GetCapability/FUM
│   │   ├── tpm_crypt.c             # Crypto primitives (SHA-256, RSA, AES, RNG)
│   │   ├── tpm_object.c            # Transient object slots, Name computation
│   │   ├── tpm_load.c              # TPM2_Load with integrity validation
│   │   ├── tpm_hierarchy.c         # Hierarchy seeds and handle normalization
│   │   ├── tpm_drbg.c              # Deterministic RNG (seeded DRBG for CreatePrimary)
│   │   ├── tpm_ticket.c            # HMAC-based creation tickets
│   │   ├── tpm_marshal.c           # FIFO marshal/unmarshal helpers
│   │   ├── tpm_marshal_tpm.c       # Canonical marshaling for TPMT_PUBLIC
│   │   ├── tpm_auth.c              # Password-session parsing
│   │   └── NvStorage.c             # In-memory NV index storage
│   ├── hw/arm/
│   │   ├── s32k358_mcu.c           # MCU model (peripherals integration)
│   │   └── s32k3x8evb-q289.c      # Board definition (S32K3X8EVB-Q289)
│   └── include/hw/misc/
│       ├── s32k358_tpm.h            # Device state struct, register fields
│       ├── tpm2_spec_protocol.h     # Protocol types, constants, I/O structs
│       ├── tpm_crypt.h              # Crypto API declarations
│       └── tpm_create_primary.h     # Umbrella header for object helpers
│
├── firmware/                        # S32K358 verification firmware
│   ├── src/
│   │   ├── main.c                  # Test orchestrator (entry point)
│   │   ├── tpm_driver.c            # Low-level MMIO driver
│   │   ├── tpm_test_smoke.c        # Smoke tests (transport, crypto, state machine)
│   │   ├── tpm_test_keymgmt.c      # Key lifecycle + verification property tests
│   │   ├── tpm_marshal.c           # Firmware-side marshaling
│   │   ├── tpm_assert.c            # Test assertion framework
│   │   ├── sha256.c               # Firmware SHA-256 (for client-side verification)
│   │   └── fifo8.c                # FIFO helper
│   ├── include/
│   │   ├── tpm2_spec_protocol.h    # Synced copy from QEMU (via Makefile)
│   │   ├── tpm_driver.h            # Driver API
│   │   ├── tpm_tests_config.h      # Test enable/disable flags
│   │   └── ...
│   ├── bin/
│   │   └── tpm_test.elf            # Compiled firmware binary
│   └── Makefile                    # Build rules, protocol header sync
│
├── docs/
│   ├── requirements/               # Specification documents
│   │   ├── 00_tpm_full_spec.md     # Consolidated specification
│   │   ├── 01_project_specification.md
│   │   ├── 02_requirements.md
│   │   ├── 03_tpm_commads_spec.md  # Command I/O tables
│   │   ├── 04_tpm_types_spec.md    # Type system reference
│   │   └── 05_tpm_state_machine_spec.md  # Operational states and transitions
│   ├── project/
│   │   └── structure.md            # Architecture guide
│   └── verification/
│       └── verification.md         # Verification properties and test plan
│
├── STATE.md                        # Current implementation status analysis
├── project-1.md                    # Project timeline and team tasks
└── README.md                       # This file
```

---

## 4. QEMU Implementation

### 4.1 Device Model and MMIO

The TPM peripheral (`s32k358_tpm.c`) registers as a QEMU `SysBusDevice` with a 16 KiB MMIO region. The register layout follows the TCG PC Client TIS specification:

| Register | Offset | Function |
| --- | --- | --- |
| `TPM_ACCESS` | 0x0000 | Locality request and grant |
| `TPM_STS` | 0x0018 | Status: `commandReady`, `tpmGo`, `dataAvail`, `Expect`, `burstCount` |
| `TPM_DATA_FIFO` | 0x0024 | Bidirectional data FIFO (input for commands, output for responses) |

The FIFO transport state machine handles the byte-stream command lifecycle:

```txt
IDLE -> READY -> RECV (writing bytes) -> EXEC (tpmGo) -> CMPL (reading response) -> IDLE
```

This transport state machine is separate from the TPM operational state machine — the former manages MMIO data flow, the latter manages the TPM's logical lifecycle.

### 4.2 Command Dispatch

When the guest asserts `TPM_STS.tpmGo`, `s32k358_tpm_process_input()` fires. It:

1. **Unmarshals the header** — extracts `tag`, `commandSize`, and `commandCode`
2. **Validates the tag** — only `TPM_ST_NO_SESSIONS` and `TPM_ST_SESSIONS` are accepted
3. **Checks operational state** — `tpm_command_allowed_in_current_mode()` enforces the initialization gate, failure mode, and FUM isolation
4. **Validates command size** — ensures the FIFO contains enough data for the declared `commandSize`
5. **Dispatches** — a `switch` on `commandCode` routes to the appropriate handler

This design means every command automatically inherits header validation, state gating, and size checking without per-command boilerplate.

### 4.3 Cryptographic Primitives

All cryptography is implemented from scratch in `tpm_crypt.c` with no external dependencies:

- **SHA-256**: Full NIST FIPS 180-4 implementation with the standard compression function, message scheduling, and padding. Verified against the three official test vectors (`"abc"`, empty string, and the 448-bit NIST test).
- **RSA**: Simplified key generation (small-prime search), PKCS#1 v1.5 / PSS signing, OAEP-less encrypt/decrypt. Key sizes up to 2048 bits.
- **AES-128**: Full round implementation supporting five modes (ECB, CBC, CFB, OFB, CTR) for `TPM2_EncryptDecrypt2`.
- **DRBG**: A CTR_DRBG-inspired deterministic RNG (`tpm_drbg.c`) that derives key material from hierarchy seeds using iterative SHA-256 hashing and AES-256-ECB. This is what makes `TPM2_CreatePrimary` deterministic — the same seed and template always produce the same primary key, exactly as the TCG spec requires.

### 4.4 Object Management and Key Lifecycle

The object subsystem (`tpm_object.c`) maintains a fixed-size table of transient object slots (`MAX_LOADED_OBJECTS`). Each slot stores:

- The public area (`TPMT_PUBLIC`) with key type, attributes, and the RSA modulus
- The sensitive area (`TPMT_SENSITIVE`) with the RSA private exponent
- The object Name (SHA-256 hash of the canonical public area marshaling)
- Object attributes (primary, hierarchy affiliation, occupied flag)

**CreatePrimary** (`tpm_cmds.c`) uses a seeded DRBG to deterministically generate the primary key from the hierarchy seed + public template. It also computes creation data, a creation hash, and an HMAC-based creation ticket — all per the TCG spec.

**Create** generates a child key using the global RNG (non-deterministic), wraps the sensitive area into a `TPM2B_PRIVATE` blob with an integrity digest (`SHA256(Name || sensitive)`), and returns it without loading the object.

**Load** (`tpm_load.c`) unwraps the private blob, verifies the integrity digest to detect tampering, recomputes the Name from the public area, and installs the object into a transient slot. If the integrity check fails (e.g., the public area was modified after creation), the command returns `TPM_RCS_BINDING` — this is a real security property, not just a stub.

### 4.5 State Machine

The operational state machine (`tpm_state_machine.c`) is layered on top of the FIFO transport. It manages TPM lifecycle transitions through boolean flags in the device state:

- `initialized` — set by `TPM2_Startup`, cleared by reset
- `in_failure_mode` — entered on self-test failure, exits only on reset
- `in_fum_mode` — entered by `TPM2_FieldUpgradeStart`, exits on upgrade completion + reset
- `orderly_shutdown` / `last_shutdown_type` — track whether the prior shutdown was orderly and which type (`CLEAR` vs `STATE`)

The command admission function `tpm_command_allowed_in_current_mode()` is called before every command dispatch. It implements a priority chain: failure mode check first, then FUM check, then initialization check. Each blocked state allows only its specific escape commands (e.g., `GetTestResult` and `GetCapability` in failure mode).

`TPM2_Startup(STATE)` validates that the previous shutdown was orderly and of type `STATE` — if not, it returns `TPM_RC_NV_UNINITIALIZED`, exactly as the spec mandates for a failed resume attempt.

### 4.6 NV Storage

NV storage (`NvStorage.c`) provides in-memory index management with define, read, write, and access control. It uses a simple linked-list layout inside a 1 KiB memory region. NV indices support attributes like `OWNERREAD`, `OWNERWRITE`, `WRITEALL`, and `WRITTEN`. This exceeds the original spec (which explicitly excluded NV) but was implemented to exercise additional TPM semantics.

### 4.7 Authorization

Authorization (`tpm_auth.c`) is intentionally simplified: `TPM_ST_SESSIONS` commands have their authorization area parsed, but the password is accepted without HMAC validation. This allows the firmware to exercise the sessions wire format (which affects response framing) without the complexity of full HMAC session management.

---

## 5. Firmware and Verification

### 5.1 Firmware Architecture

The firmware (`firmware/`) is a bare-metal C application compiled for the ARM Cortex-M target on the S32K358. It communicates with the TPM peripheral through MMIO using a low-level driver (`tpm_driver.c`) that implements:

- **Locality negotiation**: Request and wait for TPM access via `TPM_ACCESS`
- **Command transmission**: Assert `commandReady`, write command bytes to `TPM_DATA_FIFO` one byte at a time (polling `TPM_STS.Expect`), then trigger execution with `TPM_STS.tpmGo`
- **Response reception**: Poll `TPM_STS.dataAvail`, read response bytes from `TPM_DATA_FIFO`
- **Typed command wrappers**: Type-safe functions for each TPM command that handle marshaling/unmarshaling of command-specific I/O structures

### 5.2 Test Organization

Tests are organized into two files:

- **`tpm_test_smoke.c`** — Standalone smoke tests that validate individual commands in isolation (state machine startup, transport framing, NV operations, Hash, Sign, VerifySignature, EncryptDecrypt2, RSA Encrypt/Decrypt, error handling)
- **`tpm_test_keymgmt.c`** — Stateful key lifecycle tests where commands share state (CreatePrimary output feeds Create, which feeds Load, which feeds Sign and ReadPublic). Also contains the verification property test groups.

The test orchestrator in `main.c` runs the state machine startup sequence first (which gates all subsequent tests), then smoke tests, then the key management suite, and finally the shutdown sequence.

### 5.3 Verification Approach

The verification properties are defined in [docs/verification/verification.md](docs/verification/verification.md) and are organized into 12 sections covering transport framing, state machine behavior, each core command, workflow integration, error handling, and data boundaries.

The firmware tests are mapped to these properties through named test groups:

| Group | Verification Section | What It Tests |
| --- | --- | --- |
| **State Machine** | S.2 | Pre-startup command rejection (`TPM_RC_INITIALIZE`), `Startup(CLEAR)`, `SelfTest`, `GetTestResult`, `GetCapability`, `Shutdown(STATE)` |
| **A** (Transport) | S.1 | Invalid tag (`TPM_RC_BAD_TAG`), unknown command code (`TPM_RC_COMMAND_CODE`), short `commandSize` (`TPM_RC_COMMAND_SIZE`) |
| **B** (CreatePrimary) | S.3 | Template attribute matching, transient handle range, Name = SHA-256(canonical public area) |
| **C** (Create) | S.4 | Parent handle validation, template rejection for invalid attributes |
| **D** (Load) | S.5 | Private blob integrity (corrupted blob -> rejection), private/public binding |
| **E** (Sign) | S.6 | Key handle validity, sign attribute enforcement, scheme validation (RSASSA/RSAPSS/NULL), empty digest rejection, Sign->VerifySignature roundtrip, wrong-digest and corrupted-signature negative tests |
| **F** (Workflow) | S.8 | Full `CreatePrimary->Create->Load->Sign` end-to-end, multiple child keys under one primary with distinct handles |
| **G** (Errors) | S.9 | `TPM_RC_HANDLE` for invalid handles, `TPM_RC_VALUE`/`TPM_RC_HASH` for malformed inputs |
| **H** (Data Sizes) | S.10 | Sized buffer enforcement (`TPM2B` with size=0), RSA modulus size matches template (2048-bit -> 256 bytes) |

In total, over **30 verification properties** are covered by dedicated firmware tests, with the remaining properties (failure mode gating, FUM isolation, Startup(STATE) error paths, reset transitions) implemented in the QEMU logic but not yet exercised by firmware tests.

---

## 6. Building and Running

### 6.1 Compiling QEMU

```bash
cd ./qemu
./configure --enable-debug --target-list=arm-softmmu
make -j8
```

### 6.2 Compiling Firmware

```bash
cd ./firmware
make
```

The Makefile automatically syncs `tpm2_spec_protocol.h` from the QEMU source to keep protocol definitions consistent.

### 6.3 Running

```bash
cd ./qemu
./build/qemu-system-arm \
    -kernel ../firmware/bin/tpm_test.elf \
    -machine s32k3x8evb-q289 \
    -nographic \
    -d guest_errors \
    -serial none -serial none -serial none -serial mon:stdio
```

### 6.4 Debugging QEMU (Host Side)

```bash
gdb ./build/qemu-system-arm
(gdb) run -kernel ../firmware/bin/tpm_test.elf -machine s32k3x8evb-q289 \
    -nographic -d guest_errors \
    -serial none -serial none -serial none -serial mon:stdio
```

### 6.5 Debugging Firmware (Guest Side)

Terminal 1 — start QEMU paused:

```bash
./build/qemu-system-arm \
    -kernel ../firmware/bin/tpm_test.elf \
    -machine s32k3x8evb-q289 \
    -nographic -d guest_errors \
    -serial none -serial none -serial none -serial mon:stdio \
    -s -S
```

Terminal 2 — attach GDB:

```bash
cd ./firmware/bin/
gdb-multiarch -q
(gdb) file tpm_test.elf
(gdb) target remote localhost:1234
(gdb) continue
```

---

## 7. Conclusion

This project delivers a fully functional TPM 2.0 simulation that meets all core specification requirements. The `CreatePrimary -> Create -> Load -> Sign` workflow is complete and verified through firmware tests that exercise over 30 distinct verification properties.

Beyond the minimum specification, the implementation provides:

- A complete operational state machine with all six states from the TCG spec (Power-Off, Initialization, Operational, Failure Mode, Field Upgrade Mode, Shutdown)
- Self-contained cryptographic primitives with no external library dependencies
- Additional commands (GetRandom, Hash, VerifySignature, RSA Encrypt/Decrypt, AES symmetric encryption, NV storage)
- Integrity-checked private blobs that detect tampering of the public area
- A deterministic DRBG that produces reproducible primary keys from hierarchy seeds

The architecture is modular and documented to support future expansion toward PCR support, persistent NV storage, and attestation commands.

For the full implementation status breakdown, see [STATE.md](STATE.md). For the architectural guide, see [docs/project/structure.md](docs/project/structure.md).

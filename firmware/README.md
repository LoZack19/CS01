# TPM 2.0 Firmware for S32K358

Verification firmware for the QEMU-based TPM 2.0 simulation peripheral
targeting the **NXP S32K358** platform.

## Overview

This firmware provides a comprehensive test suite that exercises the TPM 2.0
command interface over a memory-mapped FIFO transport layer. It demonstrates
the full key lifecycle workflow:

```
TPM2_Startup → TPM2_CreatePrimary → TPM2_Create → TPM2_Load → TPM2_Sign
```

All cryptographic operations (SHA-256, RSA) are implemented natively — no
external libraries are required.

## Directory Structure

```
firmware/
├── include/                    Header files
│   ├── tpm2_spec_protocol.h    TPM 2.0 type system and constants
│   ├── tpm_driver.h            FIFO driver and command wrappers
│   ├── tpm_platform.h          MMIO register definitions (S32K358)
│   ├── tpm_tests_config.h      Compile-time test group selection
│   ├── tpm_marshal.h           Big-endian TPMT_PUBLIC marshalling
│   ├── tpm_assert.h            Test assertion framework
│   ├── sha256.h                SHA-256 hash (FIPS 180-4)
│   └── fifo8.h                 Circular byte-FIFO
├── src/                        Source files
│   ├── main.c                  Entry point and test orchestrator
│   ├── tpm_driver.c            FIFO driver implementation (X-macros)
│   ├── tpm_marshal.c           Canonical marshalling for Name computation
│   ├── tpm_test_keymgmt.c      Key lifecycle tests (1800+ lines)
│   ├── tpm_test_smoke.c        Standalone smoke tests
│   ├── tpm_assert.c            Assertion framework implementation
│   ├── sha256.c                SHA-256 implementation
│   └── fifo8.c                 Circular FIFO implementation
├── fakeinclude/                Stub headers for host-side compilation
├── docs/doxygen/               Generated Doxygen documentation
├── Doxyfile                    Doxygen configuration
├── Makefile                    Build system
└── compile_commands.json       Clang tooling support
```

## Building

### Cross-compilation for S32K358 target

The firmware must be built using the **NXP S32 Design Studio** toolchain with
the ARM Cortex-M7 cross-compiler. The build produces `bin/tpm_test.elf`, which
is then executed by QEMU.

**Build steps:**
1. Open the project in S32 Design Studio
2. Build the firmware (the IDE will invoke the cross-compiler with the appropriate flags)
3. The output ELF file is placed in `firmware/bin/tpm_test.elf`

**Note:** The Makefile in this directory is for synchronising the QEMU header
(`tpm2_spec_protocol.h`) and does **not** compile the firmware itself.

### Running with QEMU

Once `bin/tpm_test.elf` has been built, execute it with the QEMU S32K3x8
machine model:

```bash
cd qemu
./build/qemu-system-arm -kernel ../firmware/bin/tpm_test.elf \
  -machine s32k3x8evb-q289 -nographic -d guest_errors \
  -serial none -serial none -serial none -serial mon:stdio
```

Test output will appear on the console via the emulated LPUART3.

### Generating Doxygen documentation

```bash
cd firmware
doxygen Doxyfile
# Open docs/doxygen/html/index.html in a browser
```

## Architecture

### Module Layers

| Layer | Files | Responsibility |
|-------|-------|----------------|
| **Platform** | `tpm_platform.h` | MMIO registers, debug UART, hardware constants |
| **Transport** | `tpm_driver.c/h`, `fifo8.c/h` | Byte-level I/O, locality, command flow control |
| **Protocol** | `tpm2_spec_protocol.h` | TPM 2.0 types, constants, command structures |
| **Marshal** | `tpm_marshal.c/h` | Big-endian serialisation for Name computation |
| **Crypto** | `sha256.c/h` | SHA-256 hash (firmware-side Name verification) |
| **Test** | `tpm_test_smoke.c`, `tpm_test_keymgmt.c` | Verification test suites |
| **Assert** | `tpm_assert.c/h` | Pass/fail assertion framework |

### Command Dispatch Pattern

All TPM2 command wrappers are generated via X-macros in `tpm_driver.c`:

- **`TPM2_InOut(F)`** — commands with input + output (e.g. Sign, Hash, Load)
- **`TPM2_In(F)`** — commands with input only (e.g. Startup, NV_Write)
- **`TPM2_NoInOut(F)`** — commands without input (e.g. GetTestResult)

Each expands to a complete function: build header → send → go → receive → parse.

## Test Suite

### Configuration

Tests are enabled/disabled at compile time via `tpm_tests_config.h`.
Comment out a `#define` to skip a test group.

### Test Groups

| Group | File | Verification Property | Description |
|-------|------|----------------------|-------------|
| State Machine | `tpm_test_smoke.c` | S.1 | Startup / Shutdown sequence |
| Transport | `tpm_test_smoke.c` | S.2 | Bad tag / size / CC rejection |
| CreatePrimary | `tpm_test_keymgmt.c` | S.3 | Primary key creation + Name |
| Create | `tpm_test_keymgmt.c` | S.4 | Child key creation |
| Load | `tpm_test_keymgmt.c` | S.5 | Private blob integrity |
| Sign | `tpm_test_keymgmt.c` | S.6 | Sign / Verify operations |
| ReadPublic | `tpm_test_keymgmt.c` | S.7 | Public area read-back |
| Workflow | `tpm_test_keymgmt.c` | S.8 | End-to-end integration |
| Errors | `tpm_test_smoke.c` | S.9 | Error code validation |
| Data Sizes | `tpm_test_keymgmt.c` | S.10 | Boundary checks |

### Running

The firmware runs on the QEMU S32K358 machine with the TPM peripheral enabled.
Test results are printed over LPUART3 and captured by the QEMU host.

```
[INFO] Starting TPM Test
[INFO] TPM access granted
[PASS] Startup(CLEAR) == TPM_RC_SUCCESS
[PASS] SelfTest == TPM_RC_SUCCESS
...
=== SUMMARY: 120 assertions, 0 failures ===
```

## Specification Conformance

This firmware validates conformance to the TPM 2.0 Simulation Peripheral
Specification for S32K358 as defined in `docs/requirements/00_tpm_full_spec.md`.

### Core Commands (§5)

| Command | Status |
|---------|--------|
| `TPM2_CreatePrimary` | Implemented and tested |
| `TPM2_Create` | Implemented and tested |
| `TPM2_Load` | Implemented and tested |
| `TPM2_Sign` | Implemented and tested |
| `TPM2_ReadPublic` | Implemented and tested |

### Required Workflow (§4.1)

`CreatePrimary → Create → Load → Sign` — fully verified in
`TPM2_KeyManagement_test_suite()`.

## License

See the project root `LICENSE` file for licensing information.

# Implementing TPM State Machine: Gap Analysis and Minimum Command Set

## Purpose

This report compares the current TPM implementation against the full state-machine specification in `docs/requirements/05_tpm_state_machine_spec.md`, and identifies what is missing, where it is missing, and which minimum commands should be added to improve behavioral fidelity.

---

## 1) Current implementation baseline (what exists today)

### A. Implemented state machine is transport/MMIO-oriented, not TPM operational-state oriented

Current states in `qemu/include/hw/misc/s32k358_tpm.h`:

- `TPM_S_INIT`, `TPM_S_IDLE`, `TPM_S_READY`, `TPM_S_RECV`, `TPM_S_EXEC`, `TPM_S_CMPL`

These states model FIFO command flow (ready/recv/exec/complete), not TPM lifecycle modes (Initialization, Operational, Failure, FUM).

### B. Reset behavior starts TPM effectively operational

In `qemu/hw/misc/s32k358_tpm.c`:

- `s32k358_tpm_reset()` ends with `s->tpm_state = TPM_S_IDLE;`
- there is no startup gate requiring `TPM2_Startup` before normal commands

### C. No stateful command family for lifecycle

No implementations or dispatch for:

- `TPM2_Startup`
- `TPM2_Shutdown`
- `TPM2_SelfTest`
- `TPM2_GetTestResult`
- `TPM2_GetCapability` (state properties)
- `TPM2_FieldUpgradeStart`
- `TPM2_FieldUpgradeData`

`qemu/hw/misc/s32k358_tpm.c` currently dispatches only crypto/NV/key-management commands.

### D. Protocol/type layer is missing state-machine constants/types

In `qemu/include/hw/misc/tpm2_spec_protocol.h`:

- missing TPM state response codes used by the spec (`TPM_RC_INITIALIZE`, `TPM_RC_UPGRADE`, `TPM_RC_REBOOT`, `TPM_RC_READ_ONLY`)
- missing command codes for startup/shutdown/self-test/capability/get-test-result/field-upgrade commands
- missing `TPM_SU`, startup/shutdown parameter structures, and property-tag related structures for state reporting

### E. Command-code collision that blocks proper SelfTest integration

`qemu/include/hw/misc/tpm2_spec_protocol.h` defines:

- `TPM_CC_EncryptDecrypt2 0x00000143`

But `0x00000143` is reserved in the spec set used by this project for `TPM_CC_SelfTest`. This must be resolved before adding a true `SelfTest` dispatch.

---

## 2) Missing behavior vs full state machine

## 2.1 Initialization gate is absent

Spec expectation:

- After reset/power-on, TPM waits in Initialization state
- only startup path is accepted
- normal commands return `TPM_RC_INITIALIZE`

Current gap:

- no pre-startup command filtering in `s32k358_tpm_process_input()`
- all currently implemented commands are callable immediately after reset

Where to add:

- command gating in `qemu/hw/misc/s32k358_tpm.c` (before per-command switch)
- persistent flags in `qemu/include/hw/misc/s32k358_tpm.h` (e.g., initialized/started)

## 2.2 Startup(CLEAR/STATE) and shutdown sequencing are absent

Spec expectation:

- startup behavior depends on prior shutdown type
- orderly vs non-orderly cycle reflected by state flags and error paths (`TPM_RC_NV_UNINITIALIZED`, `TPM_RC_REBOOT`)

Current gap:

- no `TPM2_Startup` / `TPM2_Shutdown`
- no tracking of last shutdown type/orderly status

Where to add:

- command implementations in `qemu/hw/misc/tpm_cmds.c` (or dedicated state file)
- dispatch entries in `qemu/hw/misc/s32k358_tpm.c`
- state fields in `qemu/include/hw/misc/s32k358_tpm.h`

## 2.3 Failure mode semantics are absent

Spec expectation:

- failure mode blocks almost all commands
- only diagnostic subset allowed (`GetTestResult`, `GetCapability`)

Current gap:

- no failure mode variable
- `TPM_RC_FAILURE` exists but is not used for global mode gating

Where to add:

- mode flag + gate in `s32k358_tpm_process_input()`
- self-test result state in TPM state struct

## 2.4 Field Upgrade Mode (FUM) is absent

Spec expectation:

- `FieldUpgradeStart` enters FUM
- only `FieldUpgradeData` accepted in FUM
- others return `TPM_RC_UPGRADE`

Current gap:

- no FUM flag/state
- no FUM commands or command filtering

Where to add:

- state flag and filter in `qemu/hw/misc/s32k358_tpm.c`
- command handlers in `qemu/hw/misc/tpm_cmds.c`

## 2.5 State introspection via GetCapability is absent

Spec expectation:

- ability to query `TPMA_STARTUP_CLEAR`, `TPMA_PERMANENT`, `TPMA_MODES`

Current gap:

- no `TPM2_GetCapability`
- no property tags / output structures for these state attributes in protocol header

Where to add:

- protocol constants/types in `qemu/include/hw/misc/tpm2_spec_protocol.h`
- `TPM2_GetCapability` implementation in `qemu/hw/misc/tpm_cmds.c`

---

## 3) Minimum command set to implement

To simulate TPM state behavior **more accurately** with minimal surface area, implement the following command set.

### 3.1 Core minimum (recommended first)

1. `TPM2_Startup`
2. `TPM2_Shutdown`
3. `TPM2_SelfTest`
4. `TPM2_GetTestResult`
5. `TPM2_GetCapability`

Why this is the minimum core:

- adds Initialization -> Operational transition
- enables Shutdown/Startup sequencing and resume/clear semantics
- introduces Failure mode entry/reporting and restricted command policy
- enables host-side state inspection

### 3.2 Full-state-machine minimum (includes FUM)

Add the two commands below to cover all states from the project state diagram:

1. `TPM2_FieldUpgradeStart`
2. `TPM2_FieldUpgradeData`

Without 6+7, FUM cannot be entered or exercised.

---

## 4) File-by-file implementation map

## 4.1 `qemu/include/hw/misc/tpm2_spec_protocol.h`

Add:

- state response codes: `TPM_RC_INITIALIZE`, `TPM_RC_UPGRADE`, `TPM_RC_REBOOT`, `TPM_RC_READ_ONLY`
- command codes: startup/shutdown/self-test/get-test-result/get-capability/field-upgrade
- `TPM_SU` enum constants (`TPM_SU_CLEAR`, `TPM_SU_STATE`)
- command I/O structs for the 7 state commands
- capability property tags (`TPM_PT_PERMANENT`, `TPM_PT_STARTUP_CLEAR`, `TPM_PT_MODES`) and minimal response structures

Also fix command-code collision for `TPM_CC_EncryptDecrypt2` vs `TPM_CC_SelfTest`.

## 4.2 `qemu/include/hw/misc/s32k358_tpm.h`

Extend `S32k358TPMState` with operational-lifecycle fields, for example:

- `bool initialized`
- `bool in_failure_mode`
- `bool in_fum_mode`
- `bool orderly_shutdown`
- `TPM_SU last_shutdown_type`
- self-test status and optional test-result payload
- permanent/startup-clear/modes bitfields or equivalent backing flags

Keep MMIO/FIFO state (`TPM_S_*`) separate from operational mode.

## 4.3 `qemu/hw/misc/s32k358_tpm.c`

Add command admission policy in `s32k358_tpm_process_input()`:

- if not initialized: allow only `Startup` (and optionally limited diagnostics) else return `TPM_RC_INITIALIZE`
- if failure mode: allow only `GetTestResult`/`GetCapability` else return `TPM_RC_FAILURE`
- if FUM mode: allow only `FieldUpgradeData` else return `TPM_RC_UPGRADE`

Add dispatch cases for the new state commands and wire handlers.

Adjust reset/realize initialization so reset enters Initialization semantics (not fully operational).

## 4.4 `qemu/hw/misc/tpm_cmds.c`

Implement minimal logic for:

- `TPM2_Startup`: validate startup type and prior shutdown context, set initialized/flags
- `TPM2_Shutdown`: record orderly shutdown type (`CLEAR`/`STATE`)
- `TPM2_SelfTest`: set/clear self-test status; simulate failure injection path
- `TPM2_GetTestResult`: report test status/failure details
- `TPM2_GetCapability`: return the three state-related properties
- `TPM2_FieldUpgradeStart`: enter FUM when authorized policy is satisfied (simplified model can use fixed check)
- `TPM2_FieldUpgradeData`: consume data blocks and keep FUM isolation rules

---

## 5) Recommended sequencing (smallest-risk integration order)

1. Add protocol constants/types + resolve command-code collision.
2. Add TPM operational flags in state struct.
3. Implement and gate `Startup` + `Shutdown`.
4. Implement `SelfTest` + `GetTestResult` and failure-mode filtering.
5. Implement `GetCapability` state-property reporting.
6. Implement `FieldUpgradeStart` + `FieldUpgradeData` and FUM filtering.

This order enables incremental verification while preserving current command functionality.

---

## 6) Summary

The current model correctly simulates MMIO/FIFO command transport but does **not** implement TPM lifecycle states from the full spec. The practical minimum to improve state fidelity is:

- Core: `Startup`, `Shutdown`, `SelfTest`, `GetTestResult`, `GetCapability`
- Full state coverage: add `FieldUpgradeStart`, `FieldUpgradeData`

Primary implementation touchpoints are:

- `qemu/include/hw/misc/tpm2_spec_protocol.h`
- `qemu/include/hw/misc/s32k358_tpm.h`
- `qemu/hw/misc/s32k358_tpm.c`
- `qemu/hw/misc/tpm_cmds.c`

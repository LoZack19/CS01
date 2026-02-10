# Fix Plan: TPM `CreatePrimary` Sessions Stall and Related Bugs

## Context

The firmware stalls when executing `TPM2_CreatePrimary` with `TPM_ST_SESSIONS`
(tag `0x8002`). QEMU processes the command but never finalizes the response
state machine, so the firmware polls `dataAvail` forever.

Additionally, the auth area marshaling in `tpm_auth.c` uses manual byte-by-byte
big-endian encoding — a deviation from the rest of the codebase which uses
`__packed` structs with `MARSHAL`/`UNMARSHAL`. This plan eliminates that
deviation by defining proper wire-format structs for the auth areas and using
the standard macros everywhere.

### Wire format (both sides use raw `__packed` struct marshaling)

**Command** (`firmware/src/main.c:1005-1009`):
```
[Header 10B] [Params sizeof(In)] [AuthCommandArea]
```

**Response** expected by firmware (`firmware/src/main.c:1051-1054`):
```
[Header 10B] [AuthResponseArea] [Output sizeof(Out)]
```

Firmware calls `skip_auth_response_area()` **before** `tpm_receive(&out, …)`.

---

## Bugs to Fix

### Bug 1 (CRITICAL) — Sessions path never finalizes TPM state machine

**File:** `qemu/hw/misc/s32k358_tpm.c:264-284`

After marshaling the sessions response the code does `return` without:

| Missing operation | Effect |
|---|---|
| `fifo8_reset(&s->infifo)` | Stale input data left over |
| `s->tpm_state = TPM_S_CMPL` | State stuck in `TPM_S_EXEC` |
| set `R_TPM_STS_dataAvail_MASK` | **Firmware polls this forever — stall** |
| set `R_TPM_STS_commandReady_MASK` | Device never signals ready |
| clear `R_TPM_STS_Expect_MASK` | Expect flag stays asserted |
| update `burstCount` | Firmware reads 0 burst length |

### Bug 2 (CRITICAL) — Auth/output response order mismatch

**File:** `qemu/hw/misc/s32k358_tpm.c:274-277`

QEMU sends `[Header][Output][Auth]` but firmware expects
`[Header][Auth][Output]`. Also, `responseSize` on the error path is
overstated (includes sizeof(out) even when only header + auth is sent).

### Bug 3 — Auth area uses manual byte encoding (deviation)

**Files:** `qemu/hw/misc/tpm_auth.c`, `firmware/src/main.c:275-330`

`ParseAuthArea()` and `MarshalAuthResponse()` hand-encode fields byte-by-byte
in big-endian. The rest of the codebase uses `__packed` structs +
`MARSHAL`/`UNMARSHAL`. This inconsistency makes the auth areas a different
encoding than everything else on the wire.

### Bug 4 — `CryptDecrypt`/`CryptEncrypt` silently swallow errors

**Files:** `qemu/hw/misc/tpm_crypt.c:490,499`, `qemu/hw/misc/tpm_crypt.h:28-33`

Both return `void`. Callers in `tpm_cmds.c` (`TPM2_RSA_Encrypt`,
`TPM2_RSA_Decrypt`) always return `TPM_RC_SUCCESS` even when the underlying
crypto fails (log evidence: `CryptDecrypt: Invalid data size 4`).

---

## Step-by-step Plan

### Step 1 — Add auth area wire-format structs to `tpm2_spec_protocol.h`

Add two new `__packed` structs that include the `authSize` prefix, right after
the existing `TPMS_AUTH_COMMAND` / `TPMS_AUTH_RESPONSE` definitions (around
line 689):

```c
/*
 * Wire-format auth areas (authSize prefix + content).
 * Used with MARSHAL/UNMARSHAL — no manual byte encoding needed.
 */
typedef struct __packed {
    UINT32 authSize;            /* sizeof(TPMS_AUTH_COMMAND) */
    TPMS_AUTH_COMMAND auth;
} TPMS_AUTH_COMMAND_AREA;

typedef struct __packed {
    UINT32 authSize;            /* sizeof(TPMS_AUTH_RESPONSE) */
    TPMS_AUTH_RESPONSE auth;
} TPMS_AUTH_RESPONSE_AREA;
```

Since this header is the source for `firmware/include/tpm2_spec_protocol.h`
(via the firmware `Makefile`), both sides get the types automatically.

**File:** `qemu/include/hw/misc/tpm2_spec_protocol.h`

### Step 2 — Extract response-finalization helper

Create `tpm_finalize_response()` in `qemu/hw/misc/tpm_cmds.c` with the state
machine operations currently inline in `tpm_send_response()` (lines 44-56).
Add its prototype to `qemu/include/hw/misc/s32k358_tpm.h`.

Refactor `tpm_send_response()` to call the new helper.

```c
void tpm_finalize_response(S32k358TPMState *s)
{
    fifo8_reset(&s->infifo);
    s->tpm_state = TPM_S_CMPL;
    s->tpm_sts |= R_TPM_STS_dataAvail_MASK;
    s->tpm_sts |= R_TPM_STS_commandReady_MASK;
    s->tpm_sts &= ~R_TPM_STS_Expect_MASK;
    s->tpm_sts &= ~R_TPM_STS_burstCount_MASK;
    s->tpm_sts |= (fifo8_num_used(&s->outfifo)
                    << R_TPM_STS_burstCount_SHIFT)
                  & R_TPM_STS_burstCount_MASK;
}
```

**Files:**
- `qemu/include/hw/misc/s32k358_tpm.h` — add prototype
- `qemu/hw/misc/tpm_cmds.c` — add body, refactor `tpm_send_response()`

### Step 3 — Rewrite `tpm_auth.c` to use MARSHAL/UNMARSHAL

Replace the manual byte-by-byte implementations:

**`ParseAuthArea`** — replace manual big-endian parsing with:

```c
TPM_RC ParseAuthArea(Fifo8 *fifo, TPMS_AUTH_COMMAND *authCmd)
{
    if (authCmd == NULL || fifo == NULL)
        return TPM_RC_FAILURE;
    if (fifo8_num_used(fifo) < sizeof(TPMS_AUTH_COMMAND_AREA))
        return TPM_RC_COMMAND_SIZE;

    TPMS_AUTH_COMMAND_AREA area;
    UNMARSHAL(&area, fifo);

    if (area.auth.sessionHandle != TPM_RS_PW)
        return TPM_RC_HANDLE;

    *authCmd = area.auth;
    return TPM_RC_SUCCESS;
}
```

**`MarshalAuthResponse`** — replace manual byte pushing with:

```c
void MarshalAuthResponse(Fifo8 *fifo)
{
    if (fifo == NULL) return;

    TPMS_AUTH_RESPONSE_AREA area = {
        .authSize = sizeof(TPMS_AUTH_RESPONSE),
        .auth     = { /* nonce, attrs, hmac all zero-init */ }
    };
    MARSHAL(fifo, &area);
}
```

**File:** `qemu/hw/misc/tpm_auth.c`

### Step 4 — Fix sessions response path in `s32k358_tpm.c`

In the `TPM_CC_CreatePrimary` / `hasAuth` branch (lines 264-284):

1. **Swap auth/output order** — `MarshalAuthResponse` before output.
2. **Fix `responseSize`** — error path is header + auth only, no output.
3. **Call `tpm_finalize_response(s)` + log** at the end.

```c
if (hasAuth) {
    tpm_rsp_header_t rsp = {
        .tag = TPM_ST_SESSIONS,
        .responseCode = rc
    };

    if (rc == TPM_RC_SUCCESS) {
        rsp.responseSize = sizeof(rsp)
                         + sizeof(TPMS_AUTH_RESPONSE_AREA)
                         + sizeof(create_primary_out);
    } else {
        rsp.responseSize = sizeof(rsp)
                         + sizeof(TPMS_AUTH_RESPONSE_AREA);
    }

    MARSHAL(&s->outfifo, &rsp);
    MarshalAuthResponse(&s->outfifo);              /* auth first */
    if (rc == TPM_RC_SUCCESS) {
        MARSHAL(&s->outfifo, &create_primary_out); /* output second */
    }

    qemu_log_mask(LOG_GUEST_ERROR,
                  "(INFO) TPM: Command completed, rc=0x%X, "
                  "response size=%u\n", rc, rsp.responseSize);
    tpm_finalize_response(s);
}
```

**File:** `qemu/hw/misc/s32k358_tpm.c`

### Step 5 — Propagate `CryptEncrypt`/`CryptDecrypt` errors

#### 5a — Change return type to `TPM_RC`

In each function, replace `return;` on error branches with
`return TPM_RC_VALUE;` (key-size or data-size errors) or
`return TPM_RC_VALUE;` (padding error). Return `TPM_RC_SUCCESS` on normal
path.

**Files:**
- `qemu/hw/misc/tpm_crypt.h` — change prototypes from `void` to `TPM_RC`
- `qemu/hw/misc/tpm_crypt.c` — change implementations

#### 5b — Check return values in callers

In `qemu/hw/misc/tpm_cmds.c`:

**`TPM2_RSA_Encrypt`** (~line 392):
```c
TPM_RC crypt_rc = CryptEncrypt(…);
if (crypt_rc != TPM_RC_SUCCESS) return crypt_rc;
```

**`TPM2_RSA_Decrypt`** (~line 408):
```c
TPM_RC crypt_rc = CryptDecrypt(…);
if (crypt_rc != TPM_RC_SUCCESS) return crypt_rc;
```

### Step 6 — Update firmware to use struct-based auth areas

Replace the manual byte-encoding functions with `__packed` struct + raw send/receive.

#### 6a — `tpm_send_auth_area()` → struct-based

```c
static void tpm_send_auth_area(void) {
    TPMS_AUTH_COMMAND_AREA area = {
        .authSize = sizeof(TPMS_AUTH_COMMAND),
        .auth = {
            .sessionHandle = TPM_RS_PW,
            /* nonce, sessionAttributes, hmac: zero-init */
        }
    };
    tpm_send(&area, sizeof(area));
}
```

#### 6b — `skip_auth_response_area()` → struct-based

```c
static void skip_auth_response_area(void) {
    TPMS_AUTH_RESPONSE_AREA area;
    tpm_receive(&area, sizeof(area));
    /* Consumed — nothing else to do. */
}
```

#### 6c — Update `AUTH_AREA_SIZE` and command/response size calculations

```c
/* Replace old AUTH_AREA_SIZE with: */
#define AUTH_CMD_AREA_SIZE  sizeof(TPMS_AUTH_COMMAND_AREA)
#define AUTH_RSP_AREA_SIZE  sizeof(TPMS_AUTH_RESPONSE_AREA)
```

Update `commandSize`:
```c
.commandSize = sizeof(cmd) + sizeof(in) + AUTH_CMD_AREA_SIZE,
```

Update remaining-bytes calculation:
```c
size_t remaining = (rsp.responseSize >
                    sizeof(rsp) + AUTH_RSP_AREA_SIZE + sizeof(out))
    ? (size_t)rsp.responseSize - sizeof(rsp) - AUTH_RSP_AREA_SIZE - sizeof(out)
    : 0;
```

**File:** `firmware/src/main.c`

### Step 7 — Regenerate firmware header

```bash
cd firmware && make setup
```

This copies the updated `qemu/include/hw/misc/tpm2_spec_protocol.h` to
`firmware/include/tpm2_spec_protocol.h` (with the fifo8 include rewrite).

---

## File Change Summary

| File | Changes |
|------|---------|
| `qemu/include/hw/misc/tpm2_spec_protocol.h` | Add `TPMS_AUTH_COMMAND_AREA`, `TPMS_AUTH_RESPONSE_AREA` |
| `qemu/include/hw/misc/s32k358_tpm.h` | Add `tpm_finalize_response()` prototype |
| `qemu/hw/misc/tpm_cmds.c` | Add `tpm_finalize_response()`; refactor `tpm_send_response()` to use it; check `CryptEncrypt`/`CryptDecrypt` return values |
| `qemu/hw/misc/tpm_auth.c` | Rewrite `ParseAuthArea` and `MarshalAuthResponse` with `UNMARSHAL`/`MARSHAL` |
| `qemu/hw/misc/s32k358_tpm.c` | Fix sessions response: swap auth/output order, fix error-path `responseSize`, call `tpm_finalize_response()` |
| `qemu/hw/misc/tpm_crypt.h` | `CryptEncrypt`/`CryptDecrypt` → return `TPM_RC` |
| `qemu/hw/misc/tpm_crypt.c` | Return `TPM_RC` from both functions |
| `firmware/src/main.c` | `tpm_send_auth_area()` / `skip_auth_response_area()` → struct-based; update size constants |
| `firmware/include/tpm2_spec_protocol.h` | Regenerated from QEMU header |

---

## Verification

1. **Build QEMU**: `cd qemu && make -j4` — zero warnings.
2. **Regenerate firmware header**: `cd firmware && make setup`.
3. **Build firmware**: `cd firmware && make` — zero warnings.
4. **Run test**:
   ```
   cd qemu && ./build/qemu-system-arm \
       -kernel ../firmware/bin/tpm_test.elf \
       -machine s32k3x8evb-q289 -nographic -d guest_errors \
       -serial none -serial none -serial none -serial mon:stdio
   ```
5. **Expected**:
   - `TPM2_CreatePrimary` with `TPM_ST_SESSIONS` **completes** (no stall).
   - QEMU log shows `Command completed, rc=0x0` for the sessions command.
   - `TPM2_RSA_Decrypt` with bad data returns non-zero `rc`.
   - Firmware proceeds past the Key Management test suite.

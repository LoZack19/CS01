# Editing Plan — Fix Name & creationHash Mismatches

## Problem Summary

4 assertion failures (out of 43) remain, all caused by two independent bugs:

| Bug | Affects | Description |
|-----|---------|-------------|
| **A** | All 4 failures | Firmware SHA-256 K[43] constant is `0xc76fb5ae` — should be `0xc76c51a3` (FIPS 180-4) |
| **B** | Failures 1 & 4 | Firmware hashes raw `sizeof(TPMT_PUBLIC)` struct bytes; QEMU hashes a 58-byte marshaled form |

---

## Step 1 — Fix firmware SHA-256 K[43] constant

**File:** `firmware/src/sha256.c`, line 22

**Change:** Replace `0xc76fb5ae` with `0xc76c51a3`.

This is the 44th SHA-256 round constant (index 43). The correct value per FIPS 180-4
is the first 32 bits of the fractional part of the cube root of the 44th prime (193).

**Verification:** After this fix, `SHA256("") == e3b0c44298fc1c14...` and the
creationHash assertions (Failures 2 & 3) should pass immediately — both sides
hash the same 4-byte creationData buffer.

---

## Step 2 — Port `TPMT_PUBLIC_Marshal` to firmware

**Source:** `qemu/hw/misc/tpm_marshal_tpm.c` → `TPMT_PUBLIC_Marshal()`

**Target:** New file `firmware/src/tpm_marshal.c` + header `firmware/include/tpm_marshal.h`

The function performs big-endian field-by-field serialization of `TPMT_PUBLIC`:
- `type` (2 bytes BE)
- `nameAlg` (2 bytes BE)
- `objectAttributes` (4 bytes BE, bitfield → explicit bit positions)
- `authPolicy` (2-byte size + data)
- `parameters` (algorithm-dependent; only RSA needed)
- `unique` (algorithm-dependent; only RSA needed)

### 2a — Create `firmware/include/tpm_marshal.h`

```c
#ifndef TPM_MARSHAL_H
#define TPM_MARSHAL_H

#include <stdint.h>
#include "tpm2_spec_protocol.h"

/**
 * Marshal TPMT_PUBLIC into a canonical big-endian byte buffer.
 * Returns the number of bytes written into `buffer`.
 * `buffer` must be at least sizeof(TPMT_PUBLIC) bytes.
 */
uint16_t TPMT_PUBLIC_Marshal(const TPMT_PUBLIC *publicArea, uint8_t *buffer);

#endif /* TPM_MARSHAL_H */
```

### 2b — Create `firmware/src/tpm_marshal.c`

Port the logic from `qemu/hw/misc/tpm_marshal_tpm.c` lines 64–136, adapting
types from QEMU's `BYTE`/`UINT16`/`UINT32` to firmware's `uint8_t`/`uint16_t`/`uint32_t`.

The function must produce **byte-identical** output to the QEMU version for the
same input struct. The QEMU version's marshaled size for the RSA SRK template
(restricted, decrypt, AES-128-CFB, 2048-bit, exponent=0, unique.rsa.size=0) is
**26 bytes** (empty unique key), growing to **58 bytes** once the TPM fills in
`unique.rsa` with a 256-byte modulus (2 + 256).

### 2c — Update `firmware/Makefile`

No change needed — the Makefile only syncs the protocol header. The firmware
build system (external to this repo) will pick up new `.c`/`.h` files from
`src/` and `include/` automatically to produce a new build.

---

## Step 3 — Update firmware Name assertions to use marshaled form

**File:** `firmware/src/main.c`

Three locations compute `Name = nameAlg_BE(2) || SHA256(publicArea)` and
currently hash the raw struct. Each must be changed to marshal first.

### 3a — `TPM2_CreatePrimary_test()` (around line 830)

**Before:**
```c
SHA256_Init(&ctx);
SHA256_Update(&ctx, (uint8_t *)&g_create_primary_out.outPublic.publicArea,
              sizeof(TPMT_PUBLIC));
SHA256_Final(digest, &ctx);
```

**After:**
```c
uint8_t marshal_buf[sizeof(TPMT_PUBLIC)];
uint16_t marshal_len = TPMT_PUBLIC_Marshal(
    &g_create_primary_out.outPublic.publicArea, marshal_buf);
SHA256_Init(&ctx);
SHA256_Update(&ctx, marshal_buf, marshal_len);
SHA256_Final(digest, &ctx);
```

### 3b — `TPM2_Load_test()` (around line 1335)

Same pattern — replace:
```c
SHA256_Update(&ctx, (uint8_t *)pub, sizeof(TPMT_PUBLIC));
```
with:
```c
uint8_t marshal_buf[sizeof(TPMT_PUBLIC)];
uint16_t marshal_len = TPMT_PUBLIC_Marshal(pub, marshal_buf);
SHA256_Update(&ctx, marshal_buf, marshal_len);
```

### 3c — Add `#include "tpm_marshal.h"` at the top of `main.c`

---

## Step 4 — Remove diagnostic scaffolding

After all 4 assertions pass:

### 4a — `firmware/src/main.c`

Remove the `diag_hex_cmp()` helper function and all `[DIAG]` call sites
(CreatePrimary Name, CreatePrimary creationHash, Create creationHash, Load Name).

### 4b — `qemu/hw/misc/tpm_object.c`

Remove the two `qemu_log_mask` diagnostic lines added to
`PublicMarshalAndComputeName()` and `FillInCreationData()`.

---

## Verification

Rebuild firmware and QEMU, then run:
```
./build/qemu-system-arm -kernel ../firmware/bin/tpm_test.elf \
    -machine s32k3x8evb-q289 -nographic -d guest_errors \
    -serial none -serial none -serial none -serial mon:stdio
```

**Expected result:** `Total asserts: 43`, `Failed asserts: 0`.

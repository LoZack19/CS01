/*
 * tpm_util.c – Utility helpers for the TPM model.
 *
 * Class: Utility
 * Functions: MemorySet, RcSafeAddToResult
 */

#include "hw/misc/s32k358_tpm.h"
#include "hw/misc/tpm_create_primary.h"
#include <string.h>

/*
 * MemorySet – Wrapper around memset.
 *
 * Reference: ms-tpm-20-ref Memory.c MemorySet()
 */
void MemorySet(void *dest, int val, size_t size)
{
    if (dest != NULL) {
        memset(dest, val, size);
    }
}

/*
 * RcSafeAddToResult – Combine a base return code with a modifier.
 *
 * In the real reference the modifier encodes which parameter or handle
 * caused the failure so that the caller can produce a fully-qualified
 * return code.  The operation is a simple OR because the modifier bits
 * never overlap with the base-error bits for FMT1 return codes.
 *
 * Reference: ms-tpm-20-ref ResponseCodeProcessing.c RcSafeAddToResult()
 */
TPM_RC RcSafeAddToResult(TPM_RC result, TPM_RC modifier)
{
    /* If result is already a FMT1 error (bit 7 set), add the modifier. */
    if (result & RC_FMT1) {
        return result + modifier;
    }
    /* For non-FMT1 errors, the modifier is not applicable. */
    return result;
}

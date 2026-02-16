/**
 * @file   tpm_util.c
 * @brief  Utility helpers for the TPM model.
 *
 * Provides low-level utility functions (memory fill, return-code
 * composition) used across the TPM implementation.
 *
 * @see ms-tpm-20-ref Memory.c, ResponseCodeProcessing.c
 */

#include "hw/misc/s32k358_tpm.h"
#include "hw/misc/tpm_create_primary.h"
#include <string.h>

/**
 * @brief  Wrapper around @c memset with a @c NULL guard.
 *
 * @param[out] dest  Destination buffer (may be @c NULL).
 * @param[in]  val   Fill byte value.
 * @param[in]  size  Number of bytes to fill.
 *
 * @see ms-tpm-20-ref Memory.c MemorySet()
 */
void MemorySet(void *dest, int val, size_t size)
{
    if (dest != NULL) {
        memset(dest, val, size);
    }
}

/**
 * @brief Combine a base return code with a parameter/handle modifier.
 *
 * For FMT1 errors (@c RC_FMT1 bit set) the modifier encodes the
 * parameter or handle index that caused the failure.  The modifier
 * bits never overlap the base-error bits, so the combination is an
 * addition.
 *
 * @param[in] result    Base return code.
 * @param[in] modifier  Parameter/handle modifier (e.g. @c TPM_RC_P +
 *                      @c TPM_RC_1).
 * @return Fully-qualified return code.
 *
 * @see ms-tpm-20-ref ResponseCodeProcessing.c RcSafeAddToResult()
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

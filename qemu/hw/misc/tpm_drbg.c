/**
 * @file   tpm_drbg.c
 * @brief  Deterministic Random Bit Generator (CTR_DRBG) for the TPM model.
 *
 * Provides a simplified educational implementation of CTR_DRBG based on
 * AES-256 as described in TPM 2.0 Part 1 Section B.5.
 *
 * @par Implementation
 * - **Seed Derivation** – Iterative SHA-256 KDF over
 *   (counter || seed || purpose || name || additional) producing
 *   @c DRBG_SEED_SIZE_BYTES.
 * - **Random Generation** – AES-256-ECB encryption of an incrementing
 *   128-bit counter block using the derived seed as key.
 * - **State** – @c DRBG_STATE holds a magic number, reseed counter,
 *   seed, and lastValue (counter block).
 *
 * @par Simplifications
 * - No entropy collection (uses provided seed directly).
 * - No prediction resistance.
 * - No personalization string beyond the purpose label.
 * - Uses AES-ECB instead of the full CTR_DRBG construction.
 *
 * @note Uses NIST-approved primitives (SHA-256, AES-256).  Not intended
 *       for production cryptographic key generation.
 *
 * @see NIST SP 800-90A
 * @see ms-tpm-20-ref CryptRand.c
 */

#include "hw/misc/s32k358_tpm.h"
#include "hw/misc/tpm_create_primary.h"
#include "hw/misc/tpm_crypt.h"
#include <string.h>

/* ---- Internal helpers ------------------------------------------------ */

/**
 * @brief Mix seed, purpose, name, and additional data into a DRBG seed.
 *
 * Each 32-byte block of the output seed is computed as:
 * H(counter || seed || purpose || name || additional), where counter
 * is a big-endian 32-bit integer incremented per block.
 *
 * @param[out] out         Derived seed (@c DRBG_SEED_SIZE_BYTES bytes).
 * @param[in]  seed        Input seed (e.g. hierarchy primary seed).
 * @param[in]  purpose     ASCII label (no NUL terminator used).
 * @param[in]  name        Object Name (may be @c NULL).
 * @param[in]  additional  Additional data (may be @c NULL).
 */
static void DrbgDerivation(DRBG_SEED *out,
                           const TPM2B *seed,
                           const char *purpose,
                           const TPM2B *name,
                           const TPM2B *additional)
{
    /*
     * Build an input buffer:
     *   counter (4 bytes) || seed || purpose || name || additional
     *
     * Then hash it iteratively to fill DRBG_SEED_SIZE_BYTES bytes.
     */
    BYTE inputBuf[4 + 64 + 64 + sizeof(TPMU_NAME) + sizeof(TPMU_HA)];
    UINT16 inputLen = 0;
    UINT32 counter;
    UINT16 remaining;
    UINT16 offset;

    /* Reserve 4 bytes for the counter – filled below per iteration. */
    inputLen = 4;

    /* Append seed */
    if (seed != NULL && seed->size > 0) {
        UINT16 copyLen = seed->size;
        if (copyLen > 64) {
            copyLen = 64;
        }
        memcpy(&inputBuf[inputLen], seed->buffer, copyLen);
        inputLen += copyLen;
    }

    /* Append purpose label (ASCII, no NUL terminator) */
    if (purpose != NULL) {
        size_t len = strlen(purpose);
        if (len > 64) {
            len = 64;
        }
        memcpy(&inputBuf[inputLen], purpose, len);
        inputLen += (UINT16)len;
    }

    /* Append name */
    if (name != NULL && name->size > 0) {
        UINT16 copyLen = name->size;
        if (copyLen > sizeof(TPMU_NAME)) {
            copyLen = sizeof(TPMU_NAME);
        }
        memcpy(&inputBuf[inputLen], name->buffer, copyLen);
        inputLen += copyLen;
    }

    /* Append additional data */
    if (additional != NULL && additional->size > 0) {
        UINT16 copyLen = additional->size;
        if (inputLen + copyLen > sizeof(inputBuf)) {
            copyLen = (UINT16)(sizeof(inputBuf) - inputLen);
        }
        memcpy(&inputBuf[inputLen], additional->buffer, copyLen);
        inputLen += copyLen;
    }

    /* Iteratively hash to fill the seed buffer. */
    remaining = DRBG_SEED_SIZE_BYTES;
    offset = 0;
    counter = 1;

    while (remaining > 0) {
        BYTE digest[SHA256_DIGEST_SIZE];
        UINT16 chunk;

        /* Write counter into the first 4 bytes (big-endian). */
        inputBuf[0] = (BYTE)(counter >> 24);
        inputBuf[1] = (BYTE)(counter >> 16);
        inputBuf[2] = (BYTE)(counter >> 8);
        inputBuf[3] = (BYTE)(counter);

        SHA256_Calculate(inputBuf, inputLen, digest);

        chunk = remaining > SHA256_DIGEST_SIZE
                    ? SHA256_DIGEST_SIZE
                    : remaining;
        memcpy(&out->bytes[offset], digest, chunk);

        offset    += chunk;
        remaining -= chunk;
        counter++;
    }
}

/* ---- Public API ------------------------------------------------------ */

/**
 * @brief Derive a DRBG state from a primary seed and contextual data.
 *
 * Initialises @p drbgState, derives the internal seed via the KDF,
 * and zeroes the counter block.
 *
 * @param[out] drbgState   DRBG state to instantiate.
 * @param[in]  seed        Primary seed.
 * @param[in]  purpose     KDF label string.
 * @param[in]  name        Object Name (may be @c NULL).
 * @param[in]  additional  Additional data (may be @c NULL).
 * @return @c TPM_RC_SUCCESS, or @c TPM_RC_FAILURE.
 *
 * @see ms-tpm-20-ref CryptRand.c DRBG_InstantiateSeeded()
 */
TPM_RC DRBG_InstantiateSeeded(DRBG_STATE *drbgState,
                              const TPM2B *seed,
                              const char  *purpose,
                              const TPM2B *name,
                              const TPM2B *additional)
{
    if (drbgState == NULL) {
        return TPM_RC_FAILURE;
    }

    memset(drbgState, 0, sizeof(DRBG_STATE));

    /* Mark the state as valid. */
    drbgState->magic = DRBG_MAGIC;
    drbgState->reseedCounter = 1;

    /* Derive the seed with the KDF / derivation function. */
    /* Use local variable to avoid taking address of packed member. */
    DRBG_SEED derivedSeed;
    DrbgDerivation(&derivedSeed, seed, purpose, name, additional);
    drbgState->seed = derivedSeed;

    /* Zero the counter block (lastValue). */
    memset(drbgState->lastValue, 0, sizeof(drbgState->lastValue));

    return TPM_RC_SUCCESS;
}

/**
 * @brief Securely zeroize the DRBG state.
 *
 * @param[in,out] drbgState  State to clear.
 * @return @c TPM_RC_SUCCESS, or @c TPM_RC_VALUE if @p drbgState is
 *         @c NULL.
 *
 * @see ms-tpm-20-ref CryptRand.c DRBG_Uninstantiate()
 */
TPM_RC DRBG_Uninstantiate(DRBG_STATE *drbgState)
{
    if (drbgState == NULL) {
        return TPM_RC_VALUE;
    }

    memset(drbgState, 0, sizeof(DRBG_STATE));
    return TPM_RC_SUCCESS;
}

/**
 * @brief Produce pseudo-random bytes from the DRBG state.
 *
 * Simplified CTR_DRBG_Generate:
 * 1. Increment the 128-bit counter (@c lastValue).
 * 2. AES-ECB-encrypt the counter using the first 256 bits of the seed.
 * 3. Copy the cipher text to @p random.
 *
 * @param[in,out] state       DRBG state (cast to @c RAND_STATE).
 * @param[out]    random      Output buffer.
 * @param[in]     randomSize  Requested byte count.
 * @return Number of bytes actually generated.
 *
 * @see ms-tpm-20-ref CryptRand.c DRBG_Generate()
 */
UINT16 DRBG_Generate(RAND_STATE *state, BYTE *random, UINT16 randomSize)
{
    DRBG_STATE *drbg = (DRBG_STATE *)state;
    BYTE block[AES_MAX_BLOCK_SIZE];
    UINT16 generated = 0;
    UINT16 chunkSize;

    if (drbg == NULL || random == NULL || randomSize == 0) {
        return 0;
    }

    /* Validate magic. */
    if (drbg->magic != DRBG_MAGIC) {
        return 0;
    }

    while (generated < randomSize) {
        /* Increment the 128-bit counter (lastValue) – treated as a
         * big-endian integer stored in four 32-bit words. */
        int carry = 1;
        for (int i = 3; i >= 0 && carry; i--) {
            UINT64 tmp = (UINT64)drbg->lastValue[i] + carry;
            drbg->lastValue[i] = (UINT32)tmp;
            carry = (int)(tmp >> 32);
        }

        /* Encrypt the counter block with the first 256 bits of the
         * seed as AES-256 key, producing one 16-byte block. */
        {
            BYTE counterBlock[AES_MAX_BLOCK_SIZE];
            /* Pack lastValue[] into counterBlock in big-endian. */
            for (int i = 0; i < 4; i++) {
                counterBlock[i * 4 + 0] = (BYTE)(drbg->lastValue[i] >> 24);
                counterBlock[i * 4 + 1] = (BYTE)(drbg->lastValue[i] >> 16);
                counterBlock[i * 4 + 2] = (BYTE)(drbg->lastValue[i] >> 8);
                counterBlock[i * 4 + 3] = (BYTE)(drbg->lastValue[i]);
            }

            TPM_AES_ECB_Encrypt(counterBlock, AES_MAX_BLOCK_SIZE,
                                drbg->seed.bytes, AES_MAX_KEY_SIZE_BITS / 8,
                                block);
        }

        chunkSize = randomSize - generated;
        if (chunkSize > AES_MAX_BLOCK_SIZE) {
            chunkSize = AES_MAX_BLOCK_SIZE;
        }
        memcpy(&random[generated], block, chunkSize);
        generated += chunkSize;

        drbg->reseedCounter++;
    }

    return generated;
}

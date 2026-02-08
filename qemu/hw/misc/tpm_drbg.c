/*
 * tpm_drbg.c – Deterministic Random Bit Generator for the TPM model.
 *
 * Class: DRBG
 * Functions: DRBG_InstantiateSeeded, DRBG_Uninstantiate, DRBG_Generate
 *
 * OVERVIEW:
 * The TPM specification (Part 1, §B.5) describes a CTR_DRBG based on
 * AES-256. This file provides a simplified educational implementation that:
 *   1. Uses SHA-256 for seed derivation (KDF)
 *   2. Uses AES-256-ECB for pseudorandom output generation
 *   3. Maintains a counter-based state (reseedCounter)
 *
 * IMPLEMENTATION DETAILS:
 * - Seed Derivation: Iterative SHA-256 hashing of (counter || seed ||
 *   purpose || name || additional) to produce DRBG_SEED_SIZE_BYTES
 * - Random Generation: AES-256-ECB encryption of incrementing counter
 *   blocks using the derived seed as the key
 * - State: DRBG_STATE contains magic number, reseedCounter, seed, and
 *   lastValue (counter block)
 *
 * SIMPLIFICATIONS FROM SPEC:
 * - No entropy collection (uses provided seed directly)
 * - No prediction resistance
 * - No personalization string beyond the purpose label
 * - Simplified reseed counter (increments per block, no limit checking)
 * - Uses AES-ECB instead of full CTR_DRBG construction
 *
 * SECURITY NOTES:
 * This implementation uses NIST-approved primitives (SHA-256, AES-256)
 * and is suitable for an educational TPM where:
 * - The primary seed comes from a secure hierarchy seed
 * - Output is used for key generation and nonces (not for cryptographic
 *   keys in production systems)
 * - Deterministic output is acceptable (same seed → same keys)
 *
 * For production use, consider replacing with a library implementation
 * of NIST SP 800-90A CTR_DRBG.
 *
 * Reference: ms-tpm-20-ref CryptRand.c, NIST SP 800-90A
 */

#include "hw/misc/s32k358_tpm.h"
#include "hw/misc/tpm_create_primary.h"
#include "hw/misc/tpm_crypt.h"
#include <string.h>

/* -----------------------------------------------------------------------
 * Internal helpers
 * ----------------------------------------------------------------------- */

/*
 * Derivation function – Mix seed, purpose, name, additional into
 * a DRBG_SEED.  We use iterated SHA-256: each 32-byte block of the seed
 * is computed as  H(counter || seed || purpose || name || additional).
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

/* -----------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */

/*
 * DRBG_InstantiateSeeded – Derive a DRBG state from a primary seed and
 * contextual data (purpose/label, name, additional).
 *
 * Reference: ms-tpm-20-ref CryptRand.c  DRBG_InstantiateSeeded()
 *            lines 610-700
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

/*
 * DRBG_Uninstantiate – Securely zeroize the DRBG state.
 *
 * Reference: ms-tpm-20-ref CryptRand.c  DRBG_Uninstantiate()
 */
TPM_RC DRBG_Uninstantiate(DRBG_STATE *drbgState)
{
    if (drbgState == NULL) {
        return TPM_RC_VALUE;
    }

    memset(drbgState, 0, sizeof(DRBG_STATE));
    return TPM_RC_SUCCESS;
}

/*
 * DRBG_Generate – Produce pseudorandom bytes from the DRBG state.
 *
 * This is a simplified CTR_DRBG_Generate:
 *   – Increment the block counter (lastValue).
 *   – Encrypt the counter with AES-ECB using the first 256 bits of
 *     the seed as the key.
 *   – Copy the cipher text to the output.
 *
 * Returns the number of bytes actually generated.
 *
 * Reference: ms-tpm-20-ref CryptRand.c  DRBG_Generate() lines 750-904
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

/**
 * @file sha256.h
 * @brief SHA-256 hash (FIPS 180-4) used for TPM Name and integrity computations.
 *
 * Standalone implementation with no external dependencies.
 * Used by the firmware to verify creationHash, compute object Names
 * (nameAlg || H(TPMT_PUBLIC)), and validate creationTicket digests
 * as required by the TPM 2.0 specification (§4.5, §5.2).
 */

#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief SHA-256 incremental hashing context.
 *
 * Maintains partial-block state so that data can be fed in
 * arbitrarily sized chunks via SHA256_Update().
 */
typedef struct {
    uint8_t  data[64];   /**< Partial block buffer (512 bits). */
    uint32_t datalen;    /**< Bytes currently in @c data.      */
    uint64_t bitlen;     /**< Total bits processed so far.     */
    uint32_t state[8];   /**< Intermediate hash value (H0-H7). */
} SHA256_CTX;

/**
 * @brief Initialise the context with the SHA-256 IV (FIPS 180-4 §5.3.3).
 */
void SHA256_Init(SHA256_CTX *ctx);

/**
 * @brief Feed @p len bytes of @p data into the hash.
 */
void SHA256_Update(SHA256_CTX *ctx, const uint8_t *data, size_t len);

/**
 * @brief Finalise the hash and write the 32-byte digest to @p hash.
 *
 * The context is consumed and must not be reused without a new Init().
 */
void SHA256_Final(uint8_t hash[32], SHA256_CTX *ctx);

#endif /* SHA256_H */

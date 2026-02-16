/**
 * @file   tpm_ticket.c
 * @brief  Creation-ticket computation for the TPM model.
 *
 * A creation ticket is an HMAC over the object Name and the creation
 * hash, keyed with the hierarchy proof.  This simplified model uses
 * HMAC-SHA-256 with a static all-zero hierarchy proof.
 *
 * @see ms-tpm-20-ref Ticket.c / Ticket_fp.h
 */

#include "hw/misc/s32k358_tpm.h"
#include "hw/misc/tpm_create_primary.h"
#include "hw/misc/tpm_crypt.h"
#include <string.h>

/* ---- Internal helpers ------------------------------------------------ */

#define HMAC_BLOCK_SIZE  64  /**< SHA-256 block size in bytes.  */
#define HMAC_DIGEST_SIZE SHA256_DIGEST_SIZE /**< HMAC output size. */

/**
 * @brief Compute HMAC-SHA-256.
 *
 * Implements RFC 2104:  
 * HMAC(K,m) = H((K’ ^ opad) || H((K’ ^ ipad) || m))
 *
 * @param[in]  key      HMAC key.
 * @param[in]  keyLen   Key length in bytes.
 * @param[in]  data     Message data.
 * @param[in]  dataLen  Message length in bytes.
 * @param[out] mac      32-byte output digest.
 */
static void hmac_sha256(const BYTE *key, UINT16 keyLen,
                        const BYTE *data, UINT16 dataLen,
                        BYTE *mac)
{
    BYTE kPrime[HMAC_BLOCK_SIZE];
    BYTE iPad[HMAC_BLOCK_SIZE];
    BYTE oPad[HMAC_BLOCK_SIZE];
    BYTE innerBuf[HMAC_BLOCK_SIZE + 512]; /* inner: ipad || data */
    BYTE outerBuf[HMAC_BLOCK_SIZE + HMAC_DIGEST_SIZE]; /* outer: opad || innerHash */
    BYTE innerHash[HMAC_DIGEST_SIZE];
    int i;

    /* Compute K' */
    memset(kPrime, 0, sizeof(kPrime));
    if (keyLen > HMAC_BLOCK_SIZE) {
        SHA256_Calculate(key, keyLen, kPrime);
    } else {
        memcpy(kPrime, key, keyLen);
    }

    /* Compute ipad / opad */
    for (i = 0; i < HMAC_BLOCK_SIZE; i++) {
        iPad[i] = kPrime[i] ^ 0x36;
        oPad[i] = kPrime[i] ^ 0x5C;
    }

    /* Inner hash: H(ipad || data) */
    memcpy(innerBuf, iPad, HMAC_BLOCK_SIZE);
    {
        UINT16 copyLen = dataLen;
        if (copyLen > sizeof(innerBuf) - HMAC_BLOCK_SIZE) {
            copyLen = (UINT16)(sizeof(innerBuf) - HMAC_BLOCK_SIZE);
        }
        memcpy(&innerBuf[HMAC_BLOCK_SIZE], data, copyLen);
        SHA256_Calculate(innerBuf, HMAC_BLOCK_SIZE + copyLen, innerHash);
    }

    /* Outer hash: H(opad || innerHash) */
    memcpy(outerBuf, oPad, HMAC_BLOCK_SIZE);
    memcpy(&outerBuf[HMAC_BLOCK_SIZE], innerHash, HMAC_DIGEST_SIZE);
    SHA256_Calculate(outerBuf, HMAC_BLOCK_SIZE + HMAC_DIGEST_SIZE, mac);
}

/* ---- Public API ------------------------------------------------------ */

/**
 * @brief Compute a @c TPMT_TK_CREATION for a newly created primary.
 *
 * Fills:
 * - @c ticket->tag       = @c TPM_ST_CREATION
 * - @c ticket->hierarchy = @p hierarchy
 * - @c ticket->digest    = HMAC_hierarchyProof( name || creationHash )
 *
 * @param[in]  hierarchy     Owning hierarchy.
 * @param[in]  name          Object Name.
 * @param[in]  creationHash  Hash of the creation data.
 * @param[out] ticket        Computed creation ticket.
 * @return @c TPM_RC_SUCCESS, or @c TPM_RC_FAILURE.
 *
 * @note The hierarchy proof is a fixed 32-byte zero buffer; a production
 *       implementation would retrieve it from NV storage.
 *
 * @see ms-tpm-20-ref Ticket.c
 */
TPM_RC TicketComputeCreation(TPMI_RH_HIERARCHY hierarchy,
                             TPM2B_NAME *name,
                             TPM2B_DIGEST *creationHash,
                             TPMT_TK_CREATION *ticket)
{
    /* Fixed hierarchy proof (32 bytes of zeroes).
     * A real implementation should retrieve this from NV storage. */
    static const BYTE hierarchyProof[SHA256_DIGEST_SIZE] = {0};
    BYTE hmacInput[sizeof(TPMU_NAME) + sizeof(TPMU_HA)];
    UINT16 hmacInputLen = 0;

    if (ticket == NULL) {
        return TPM_RC_FAILURE;
    }

    /* Fill tag and hierarchy. */
    ticket->tag       = TPM_ST_CREATION;
    ticket->hierarchy = hierarchy;
    memset(&ticket->digest, 0, sizeof(ticket->digest));

    /* Build HMAC input = name || creationHash */
    if (name != NULL && name->size > 0) {
        memcpy(&hmacInput[hmacInputLen], name->buffer, name->size);
        hmacInputLen += name->size;
    }
    if (creationHash != NULL && creationHash->size > 0) {
        memcpy(&hmacInput[hmacInputLen], creationHash->buffer,
               creationHash->size);
        hmacInputLen += creationHash->size;
    }

    /* Compute HMAC */
    hmac_sha256(hierarchyProof, SHA256_DIGEST_SIZE,
                hmacInput, hmacInputLen,
                ticket->digest.buffer);
    ticket->digest.size = SHA256_DIGEST_SIZE;

    return TPM_RC_SUCCESS;
}

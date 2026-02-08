/*
 * tpm_ticket.c – Creation-ticket computation for the TPM model.
 *
 * Class: Ticket
 * Functions: TicketComputeCreation
 *
 * A creation ticket is an HMAC over the object Name and the creation
 * hash, keyed with the hierarchy proof.  In this simplified model we
 * use SHA-256-based HMAC with a static hierarchy proof.
 *
 * Reference: ms-tpm-20-ref Ticket.c / Ticket_fp.h
 */

#include "hw/misc/s32k358_tpm.h"
#include "hw/misc/tpm_create_primary.h"
#include "hw/misc/tpm_crypt.h"
#include <string.h>

/* -----------------------------------------------------------------------
 * Simplified HMAC-SHA256
 *
 * HMAC(K,m) = H((K' ^ opad) || H((K' ^ ipad) || m))
 *   where K' = H(K) if |K| > block-size, else K zero-padded to block-size.
 * ----------------------------------------------------------------------- */

#define HMAC_BLOCK_SIZE  64  /* SHA-256 block size */
#define HMAC_DIGEST_SIZE SHA256_DIGEST_SIZE

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

/* -----------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */

/*
 * TicketComputeCreation – Compute a TPMT_TK_CREATION for a newly created
 * primary object.
 *
 * ticket.tag      = TPM_ST_CREATION
 * ticket.hierarchy = hierarchy
 * ticket.digest   = HMAC_hierarchyProof(name || creationHash)
 *
 * In a full implementation the hierarchy proof is stored in NV and is
 * unique per hierarchy.  Here we use a fixed, all-zero proof for the
 * simplified model.
 *
 * Reference: ms-tpm-20-ref  Ticket_fp.h / Ticket.c
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

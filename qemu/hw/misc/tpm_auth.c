/*
 * tpm_auth.c – Authorization area parsing for TPM commands.
 *
 * This file provides simple authorization area parsing and response
 * marshaling for TPM_ST_SESSIONS commands. For an educational TPM with
 * default empty passwords, we parse the session area and verify the
 * sessionHandle is TPM_RS_PW (password authorization), but skip HMAC
 * validation.
 *
 * Reference: TPM 2.0 Part 1, Section 19 (Authorization)
 */

#include "hw/misc/s32k358_tpm.h"
#include "hw/misc/tpm2_spec_protocol.h"
#include "qemu/fifo8.h"
#include <string.h>

/*
 * ParseAuthArea – Parse authorization area from command FIFO.
 *
 * Format: authSize (4) || sessionHandle (4) || nonce (2+N) ||
 *         sessionAttributes (1) || hmac (2+N)
 *
 * This simplified implementation:
 *   - Verifies sessionHandle == TPM_RS_PW (password authorization)
 *   - Accepts empty passwords without HMAC validation
 *   - Returns TPM_RC_SUCCESS if valid, error otherwise
 *
 * Reference: TPM 2.0 Part 1, Table 75 (TPMS_AUTH_COMMAND)
 */
TPM_RC ParseAuthArea(Fifo8 *fifo, TPMS_AUTH_COMMAND *authCmd)
{
    UINT32 authSize;

    if (authCmd == NULL || fifo == NULL) {
        return TPM_RC_FAILURE;
    }

    /* Check minimum size for authSize field. */
    if (fifo8_num_used(fifo) < 4) {
        return TPM_RC_COMMAND_SIZE;
    }

    /* Read authSize (big-endian). */
    authSize = ((UINT32)fifo8_pop(fifo) << 24) |
               ((UINT32)fifo8_pop(fifo) << 16) |
               ((UINT32)fifo8_pop(fifo) << 8) |
               (UINT32)fifo8_pop(fifo);

    /* Verify we have enough data for the auth area. */
    if (fifo8_num_used(fifo) < authSize) {
        return TPM_RC_COMMAND_SIZE;
    }

    /* Read sessionHandle (big-endian). */
    authCmd->sessionHandle = ((UINT32)fifo8_pop(fifo) << 24) |
                             ((UINT32)fifo8_pop(fifo) << 16) |
                             ((UINT32)fifo8_pop(fifo) << 8) |
                             (UINT32)fifo8_pop(fifo);

    /* Verify it's a password session (only type we support). */
    if (authCmd->sessionHandle != TPM_RS_PW) {
        return TPM_RC_HANDLE; /* Only password sessions supported. */
    }

    /* Read nonce (size + buffer). */
    authCmd->nonce.size = ((UINT16)fifo8_pop(fifo) << 8) |
                          (UINT16)fifo8_pop(fifo);

    for (UINT16 i = 0; i < authCmd->nonce.size &&
                        i < sizeof(authCmd->nonce.buffer); i++) {
        authCmd->nonce.buffer[i] = fifo8_pop(fifo);
    }

    /* Read sessionAttributes. */
    authCmd->sessionAttributes = fifo8_pop(fifo);

    /* Read HMAC/password (size + buffer). */
    authCmd->hmac.size = ((UINT16)fifo8_pop(fifo) << 8) |
                         (UINT16)fifo8_pop(fifo);

    for (UINT16 i = 0; i < authCmd->hmac.size &&
                        i < sizeof(authCmd->hmac.buffer); i++) {
        authCmd->hmac.buffer[i] = fifo8_pop(fifo);
    }

    /*
     * For educational TPM: accept empty password without validation.
     * A full implementation would compute and verify HMAC here.
     */
    return TPM_RC_SUCCESS;
}

/*
 * MarshalAuthResponse – Marshal authorization response area to output FIFO.
 *
 * Format: authSize (4) || nonce (2+0) || sessionAttributes (1) || hmac (2+0)
 *
 * For password sessions with empty passwords, we send empty nonce and HMAC.
 *
 * Reference: TPM 2.0 Part 1, Table 76 (TPMS_AUTH_RESPONSE)
 */
void MarshalAuthResponse(Fifo8 *fifo)
{
    if (fifo == NULL) {
        return;
    }

    /* Empty auth response for password sessions. */
    UINT32 authSize = 2 + 1 + 2; /* nonce (2) + attrs (1) + hmac (2) */

    /* authSize (big-endian). */
    fifo8_push(fifo, (BYTE)(authSize >> 24));
    fifo8_push(fifo, (BYTE)(authSize >> 16));
    fifo8_push(fifo, (BYTE)(authSize >> 8));
    fifo8_push(fifo, (BYTE)(authSize));

    /* nonce (empty - size = 0). */
    fifo8_push(fifo, 0);
    fifo8_push(fifo, 0);

    /* sessionAttributes. */
    fifo8_push(fifo, 0);

    /* hmac (empty - size = 0). */
    fifo8_push(fifo, 0);
    fifo8_push(fifo, 0);
}

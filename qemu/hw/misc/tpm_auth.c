/*
 * tpm_auth.c – Authorization area parsing for TPM commands.
 *
 * This file provides simple authorization area parsing and response
 * marshaling for TPM_ST_SESSIONS commands. For an educational TPM with
 * default empty passwords, we parse the session area and verify the
 * sessionHandle is TPM_RS_PW (password authorization), but skip HMAC
 * validation.
 *
 * Uses the standard MARSHAL/UNMARSHAL macros on __packed wire-format
 * structs (TPMS_AUTH_COMMAND_AREA / TPMS_AUTH_RESPONSE_AREA).
 *
 * Reference: TPM 2.0 Part 1, Section 19 (Authorization)
 */

#include "hw/misc/s32k358_tpm.h"
#include "hw/misc/tpm2_spec_protocol.h"
#include "qemu/fifo8.h"

/*
 * ParseAuthArea – Parse authorization area from command FIFO.
 *
 * Unmarshals a TPMS_AUTH_COMMAND_AREA (authSize + TPMS_AUTH_COMMAND)
 * and validates the session handle.
 *
 * Returns TPM_RC_SUCCESS if valid, error otherwise.
 */
TPM_RC ParseAuthArea(Fifo8 *fifo, TPMS_AUTH_COMMAND *authCmd)
{
    TPMS_AUTH_COMMAND_AREA area;

    if (authCmd == NULL || fifo == NULL) {
        return TPM_RC_FAILURE;
    }

    if (fifo8_num_used(fifo) < sizeof(TPMS_AUTH_COMMAND_AREA)) {
        return TPM_RC_COMMAND_SIZE;
    }

    UNMARSHAL(&area, fifo);

    /* Only password sessions supported. */
    if (area.auth.sessionHandle != TPM_RS_PW) {
        return TPM_RC_HANDLE;
    }

    *authCmd = area.auth;
    return TPM_RC_SUCCESS;
}

/*
 * MarshalAuthResponse – Marshal authorization response area to output FIFO.
 *
 * Builds a TPMS_AUTH_RESPONSE_AREA with empty nonce/HMAC and marshals it.
 */
void MarshalAuthResponse(Fifo8 *fifo)
{
    if (fifo == NULL) {
        return;
    }

    TPMS_AUTH_RESPONSE_AREA area = {
        .authSize = sizeof(TPMS_AUTH_RESPONSE),
        .auth     = { /* nonce, sessionAttributes, hmac: zero-init */ }
    };
    MARSHAL(fifo, &area);
}

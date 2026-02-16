/**
 * @file   tpm_auth.c
 * @brief  Authorization-area parsing for TPM commands.
 *
 * Provides simple authorization-area parsing and response marshaling
 * for @c TPM_ST_SESSIONS commands.  For the educational TPM only
 * password sessions (@c TPM_RS_PW) with empty passwords are supported;
 * HMAC-based sessions are not implemented.
 *
 * Uses the standard MARSHAL / UNMARSHAL macros on @c __packed
 * wire-format structs (@c TPMS_AUTH_COMMAND_AREA /
 * @c TPMS_AUTH_RESPONSE_AREA).
 *
 * @see TPM 2.0 Part 1 Section 19 – Authorization
 */

#include "hw/misc/s32k358_tpm.h"
#include "hw/misc/tpm_create_primary.h"
#include "hw/misc/tpm2_spec_protocol.h"
#include "qemu/fifo8.h"

/* See tpm_create_primary.h for documentation. */
TPM_RC ParseAuthArea(Fifo8 *fifo, TPMS_AUTH_COMMAND *authCmd) {
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

/* See tpm_create_primary.h for documentation. */
void MarshalAuthResponse(Fifo8 *fifo) {
    if (fifo == NULL) {
        return;
    }

    TPMS_AUTH_RESPONSE_AREA area = {
        .authSize = sizeof(TPMS_AUTH_RESPONSE),
        .auth = {/* nonce, sessionAttributes, hmac: zero-init */}};
    MARSHAL(fifo, &area);
}

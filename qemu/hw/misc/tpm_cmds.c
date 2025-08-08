#include "include/hw/misc/s32k358_tpm.h"

/* TPM responses */

void tpm_error_response(S32k358TPMState *s, TPM_RC rc) {
    tpm_rsp_header_t rsp_header;

    rsp_header.tag = TPM_ST_NO_SESSIONS; // No sessions for this response
    rsp_header.responseSize = sizeof(rsp_header);
    rsp_header.responseCode = rc;

    // Marshal the response header onto the output FIFO
    tpm_rsp_header_marshal(&s->outfifo, &rsp_header);

    // Update status to indicate data is available
    s->tpm_state = TPM_S_CMPL; // Transition to complete state
    s->tpm_sts |= R_TPM_STS_dataAvail_MASK;
    s->tpm_sts |= R_TPM_STS_commandReady_MASK;
}

void tpm_success_response(S32k358TPMState *s, const uint8_t *data, size_t size, void marshal_func(Fifo8 *fifo, const uint8_t *data)) {
    tpm_rsp_header_t rsp_header;

    rsp_header.tag = TPM_ST_NO_SESSIONS; // No sessions for this response
    rsp_header.responseSize = sizeof(rsp_header) + size;
    rsp_header.responseCode = TPM_RC_SUCCESS;

    // Marshal the response header onto the output FIFO
    tpm_rsp_header_marshal(&s->outfifo, &rsp_header);

    // Marshal the actual data onto the output FIFO
    marshal_func(&s->outfifo, data);

    // Update status to indicate data is available
    s->tpm_state = TPM_S_CMPL; // Transition to complete state
    s->tpm_sts |= R_TPM_STS_dataAvail_MASK;
    s->tpm_sts |= R_TPM_STS_commandReady_MASK;
    
    qemu_log_mask(LOG_GUEST_ERROR, "(INFO) TPM: Command executed successfully, response sent\n");
}

/* Auxilliary functions */

static void CryptRandomGenerate(UINT16 size, BYTE *buffer) {
    for (UINT16 i = 0; i < size; i++) {
        buffer[i] = rand() % 0x100;
    }
}

/* TPM Commands */

TPM_RC TPM2_GetRandom(GetRandom_In *in, GetRandom_Out *out) {
    // Truncate size to maximum supported digest size
    if(in->bytesRequested > sizeof(TPMU_HA)) {
        qemu_log_mask(LOG_GUEST_ERROR,
            "TPM2_GetRandom: Requested size %u exceeds maximum %zu, truncating\n",
            in->bytesRequested, sizeof(TPMU_HA)
        );

        out->randomBytes.size = sizeof(TPMU_HA);
    } else {
        qemu_log_mask(LOG_GUEST_ERROR,
            "TPM2_GetRandom: Requested size %u is within limits, generating random bytes\n",
            in->bytesRequested
        );

        out->randomBytes.size = in->bytesRequested;
    }
    
    // Generate random bytes
    CryptRandomGenerate(out->randomBytes.size, out->randomBytes.buffer);
    
    return TPM_RC_SUCCESS;
}

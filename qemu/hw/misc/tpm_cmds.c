#include "include/hw/misc/s32k358_tpm.h"

static TPM_HT HandleGetType(TPM_HANDLE handle) {
    return (TPM_HT)(handle >> HR_SHIFT);
}

/* TPM responses */

void tpm_send_response(S32k358TPMState *s, TPM_RC rc, 
                       const void *data, size_t size) {
    tpm_rsp_header_t rsp_header;

    rsp_header.tag = TPM_ST_NO_SESSIONS; // No sessions for this response
    rsp_header.responseSize = sizeof(rsp_header) + size;
    rsp_header.responseCode = TPM_RC_SUCCESS;

    // Marshal the response header onto the output FIFO
    MARSHAL(&s->outfifo, &rsp_header);

    // Marshal the actual data onto the output FIFO on success
    if (rc == TPM_RC_SUCCESS) {
        marshal(&s->outfifo, data, size);
    }

    // Update status to indicate that data is available
    s->tpm_state = TPM_S_CMPL;
    s->tpm_sts |= R_TPM_STS_dataAvail_MASK;
    s->tpm_sts |= R_TPM_STS_commandReady_MASK;

    // Update burstCount
    s->tpm_sts &= ~R_TPM_STS_burstCount_MASK;
    s->tpm_sts |= (rsp_header.responseSize << R_TPM_STS_burstCount_SHIFT) &
                  R_TPM_STS_burstCount_MASK;
    
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

TPM_RC TPM2_NV_DefineSpace(NV_DefineSpace_In* in) {
    // This command only supports TPM_HT_NV_INDEX-typed NV indices.
    if (HandleGetType(in->publicInfo.nvPublic.nvIndex) != TPM_HT_NV_INDEX) {
        return TPM_RCS_HANDLE + RC_NV_DefineSpace_publicInfo;
    }

    return NvDefineSpace(
        in->authHandle,
        &in->auth,
        &in->publicInfo.nvPublic,
        RC_NV_DefineSpace_authHandle,
        RC_NV_DefineSpace_auth,
        RC_NV_DefineSpace_publicInfo);
}

TPM_RC TPM2_NV_Write(NV_Write_In* in)
{
    NV_INDEX* nvIndex    = NvGetIndexInfo(in->nvIndex, NULL);
    TPMA_NV   attributes = nvIndex->publicArea.attributes;
    TPM_RC    result;

    // Input Validation

    // Common access checks, NvWriteAccessCheck() may return TPM_RC_NV_AUTHORIZATION
    // or TPM_RC_NV_LOCKED
    result = NvWriteAccessChecks(in->authHandle, in->nvIndex, attributes);
    if(result != TPM_RC_SUCCESS)
        return result;

    // Bits index, extend index or counter index may not be updated by
    // TPM2_NV_Write
    if(IsNvCounterIndex(attributes) || IsNvBitsIndex(attributes)
       || IsNvExtendIndex(attributes))
        return TPM_RC_ATTRIBUTES;

    // Make sure that the offset is not too large
    if(in->offset > nvIndex->publicArea.dataSize)
        return TPM_RC_VALUE;

    // Make sure that the selection is within the range of the Index
    if(in->data.size > (nvIndex->publicArea.dataSize - in->offset))
        return TPM_RC_NV_RANGE;

    // If this index requires a full sized write, make sure that input range is
    // full sized.
    // Note: if the requested size is the same as the Index data size, then offset
    // will have to be zero. Otherwise, the range check above would have failed.
    if(IS_ATTRIBUTE(attributes, TPMA_NV, WRITEALL)
       && in->data.size < nvIndex->publicArea.dataSize)
        return TPM_RC_NV_RANGE;

    // Internal Data Update

    // Perform the write.  This called routine will SET the TPMA_NV_WRITTEN
    // attribute if it has not already been SET. If NV isn't available, an error
    // will be returned.
    return NvWriteIndexData(nvIndex, in->offset, in->data.size, in->data.buffer);
}

TPM_RC TPM2_NV_Read(NV_Read_In* in, NV_Read_Out* out)
{
    NV_REF    locator;
    NV_INDEX* nvIndex = NvGetIndexInfo(in->nvIndex, &locator);
    TPM_RC    result;

    // Input Validation
    // Common read access checks. NvReadAccessChecks() may return
    // TPM_RC_NV_AUTHORIZATION, TPM_RC_NV_LOCKED, or TPM_RC_NV_UNINITIALIZED
    result = NvReadAccessChecks(
        in->authHandle, in->nvIndex, nvIndex->publicArea.attributes);
    if(result != TPM_RC_SUCCESS)
        return result;

    // Make sure the data will fit the return buffer
    if(in->size > MAX_NV_BUFFER_SIZE)
        return TPM_RC_VALUE;

    // Verify that the offset is not too large
    if(in->offset > nvIndex->publicArea.dataSize)
        return TPM_RC_VALUE;

    // Make sure that the selection is within the range of the Index
    if(in->size > (nvIndex->publicArea.dataSize - in->offset))
        return TPM_RC_NV_RANGE;

    // Command Output
    // Set the return size
    out->data.size = in->size;

    // Perform the read
    NvGetIndexData(nvIndex, locator, in->offset, in->size, out->data.buffer);

    return TPM_RC_SUCCESS;
}

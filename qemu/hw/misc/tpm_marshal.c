#include "include/hw/misc/s32k358_tpm.h"

UINT8 read_be8(Fifo8 *fifo) {
    return fifo8_pop(fifo);
}

UINT16 read_be16(Fifo8 *fifo) {
    return ((UINT16)fifo8_pop(fifo) << 8) | (UINT16)fifo8_pop(fifo);
}

UINT32 read_be32(Fifo8 *fifo) {
    return ((UINT32)fifo8_pop(fifo) << 24) |
           ((UINT32)fifo8_pop(fifo) << 16) |
           ((UINT32)fifo8_pop(fifo) << 8)  |
            (UINT32)fifo8_pop(fifo);
}

void write_be16(Fifo8 *fifo, UINT16 value) {
    fifo8_push(fifo, (value >> 8) & 0xFF);
    fifo8_push(fifo, value & 0xFF);
}

void write_be32(Fifo8 *fifo, UINT32 value) {
    fifo8_push(fifo, (value >> 24) & 0xFF);
    fifo8_push(fifo, (value >> 16) & 0xFF);
    fifo8_push(fifo, (value >> 8) & 0xFF);
    fifo8_push(fifo, value & 0xFF);
}

// Unmarshal a command header from the FIFO
void tpm_cmd_header_unmarshal(Fifo8 *fifo, tpm_cmd_header_t *header) {
    header->tag = read_be16(fifo);
    header->commandSize = read_be32(fifo);
    header->commandCode = read_be32(fifo);
}

// Marshal a response header to the FIFO
void tpm_rsp_header_marshal(Fifo8 *fifo, const tpm_rsp_header_t *header) {
    write_be16(fifo, header->tag);
    write_be32(fifo, header->responseSize);
    write_be32(fifo, header->responseCode);
}

// Unmarshal a TPM_HANDLE from the FIFO
TPM_HANDLE read_be_TPM_HANDLE(Fifo8 *fifo) {
    return (TPM_HANDLE)read_be32(fifo);
}

// Unmarshal a TPM2B_DIGEST from the FIFO
TPM2B_DIGEST read_be_TPM2B_DIGEST(Fifo8 *fifo) {
    TPM2B_DIGEST auth;
    auth.size = read_be16(fifo);
    
    for (size_t i = 0; i < sizeof(TPMU_HA); i++) {
        auth.buffer[i] = read_be8(fifo);
    }
    
    return auth;
}

// Unmarshal a TPMS_NV_PUBLIC from the FIFO
TPMS_NV_PUBLIC read_be_TPMS_NV_PUBLIC(Fifo8 *fifo) {
    TPMS_NV_PUBLIC nv_public;
    nv_public.nvIndex = read_be32(fifo);
    nv_public.nameAlg = read_be16(fifo);
    nv_public.attributes = read_be32(fifo);
    nv_public.authPolicy = read_be_TPM2B_DIGEST(fifo);
    nv_public.dataSize = read_be16(fifo);
    
    return nv_public;
}

// Unmarshal a TPM2B_NV_PUBLIC from the FIFO
TPM2B_NV_PUBLIC read_be_TPM2B_NV_PUBLIC(Fifo8 *fifo) {
    TPM2B_NV_PUBLIC nv_public;
    nv_public.size = read_be16(fifo);
    nv_public.nvPublic = read_be_TPMS_NV_PUBLIC(fifo);
    
    return nv_public;
}

// Unmarshal a GetRandom input structure from the FIFO
void get_random_in_unmarshal(Fifo8 *fifo, uint8_t *in) {
    GetRandom_In *get_random_in = (GetRandom_In *)in;
    get_random_in->bytesRequested = read_be16(fifo);
}

// Unmarshal a NV_DefineSpace input structure from the FIFO
void nv_define_space_in_unmarshal(Fifo8 *fifo, uint8_t *in) {
    NV_DefineSpace_In *nv_define_space_in = (NV_DefineSpace_In *)in;
    nv_define_space_in->authHandle = (TPMI_RH_PROVISION)read_be_TPM_HANDLE(fifo);
    nv_define_space_in->auth = (TPM2B_AUTH)read_be_TPM2B_DIGEST(fifo);
    nv_define_space_in->publicInfo = read_be_TPM2B_NV_PUBLIC(fifo);
}

// Marshal a GetRandom output structure to the FIFO
void get_random_out_marshal(Fifo8 *fifo, const uint8_t *out) {
    const GetRandom_Out *get_random_out = (const GetRandom_Out *)out;
    write_be16(fifo, get_random_out->randomBytes.size);
    for (UINT16 i = 0; i < get_random_out->randomBytes.size; i++) {
        fifo8_push(fifo, get_random_out->randomBytes.buffer[i]);
    }
}
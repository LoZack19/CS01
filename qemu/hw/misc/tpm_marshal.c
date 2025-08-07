#include "include/hw/misc/s32k358_tpm.h"

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

// Unmarshal a GetRandom input structure from the FIFO
void get_random_in_unmarshal(Fifo8 *fifo, uint8_t *in) {
    GetRandom_In *get_random_in = (GetRandom_In *)in;
    get_random_in->bytesRequested = read_be16(fifo);
}

// Marshal a GetRandom output structure to the FIFO
void get_random_out_marshal(Fifo8 *fifo, const uint8_t *out) {
    const GetRandom_Out *get_random_out = (const GetRandom_Out *)out;
    write_be16(fifo, get_random_out->randomBytes.size);
    for (UINT16 i = 0; i < get_random_out->randomBytes.size; i++) {
        fifo8_push(fifo, get_random_out->randomBytes.buffer[i]);
    }
}
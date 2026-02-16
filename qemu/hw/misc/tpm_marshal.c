/**
 * @file tpm_marshal.c
 * @brief Byte-level FIFO marshaling / unmarshaling helpers.
 *
 * Provides generic @c marshal and @c unmarshal functions that
 * copy raw bytes between a host buffer and a QEMU @c Fifo8.
 * These use native endianness — no byte-swapping is performed.
 *
 * @note For canonical big-endian marshaling of @c TPMT_PUBLIC (used in
 *       Name computation), see tpm_marshal_tpm.c.
 *
 * @see tpm_marshal_tpm.c  for TPM-specific big-endian marshaling.
 */

#include "include/hw/misc/s32k358_tpm.h"

/**
 * @brief Pop @p size bytes from @p fifo into @p data (native order).
 *
 * @param[out]    data  Destination buffer.
 * @param[in]     size  Number of bytes to read.
 * @param[in,out] fifo  Source FIFO.
 */
void unmarshal(void *data, size_t size, Fifo8 *fifo) {
    for (size_t i = 0; i < size; i++) {
        ((uint8_t *)data)[i] = fifo8_pop(fifo);
    }
}

/**
 * @brief Push @p size bytes from @p data into @p fifo (native order).
 *
 * @param[in,out] fifo  Destination FIFO.
 * @param[in]     data  Source buffer.
 * @param[in]     size  Number of bytes to write.
 */
void marshal(Fifo8 *fifo, const void *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        fifo8_push(fifo, ((uint8_t *)data)[i]);
    }
}
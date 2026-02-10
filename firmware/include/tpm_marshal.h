#ifndef TPM_MARSHAL_H
#define TPM_MARSHAL_H

#include <stdint.h>
#include "tpm2_spec_protocol.h"

/**
 * Marshal TPMT_PUBLIC into a canonical big-endian byte buffer.
 * Returns the number of bytes written into `buffer`.
 * `buffer` must be at least sizeof(TPMT_PUBLIC) bytes.
 */
uint16_t TPMT_PUBLIC_Marshal(const TPMT_PUBLIC *publicArea, uint8_t *buffer);

#endif /* TPM_MARSHAL_H */

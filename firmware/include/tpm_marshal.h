/**
 * @file tpm_marshal.h
 * @brief Canonical big-endian marshalling of TPMT_PUBLIC for Name computation.
 *
 * The TPM object Name is defined as:
 *   Name = nameAlg (2 bytes BE) || Hash_nameAlg(TPMT_PUBLIC_canonical)
 *
 * This module produces the same byte stream as the QEMU-side
 * marshaller (tpm_marshal_tpm.c), so firmware-computed Names
 * match those returned by TPM2_Load / TPM2_ReadPublic (§5.2).
 */

#ifndef TPM_MARSHAL_H
#define TPM_MARSHAL_H

#include <stdint.h>
#include "tpm2_spec_protocol.h"

/**
 * @brief Marshal a TPMT_PUBLIC into canonical big-endian form.
 *
 * Serialises @p publicArea field-by-field in TCG wire order.  Only
 * TPM_ALG_RSA is supported for the parameters/unique union branches.
 *
 * @param publicArea  Source structure (native endianness).
 * @param buffer      Destination buffer (at least sizeof(TPMT_PUBLIC) bytes).
 * @return            Number of bytes written to @p buffer, or 0 on error.
 */
uint16_t TPMT_PUBLIC_Marshal(const TPMT_PUBLIC *publicArea, uint8_t *buffer);

#endif /* TPM_MARSHAL_H */

/**
 * @file tpm_marshal_tpm.c
 * @brief Big-endian field-by-field marshaling for TPM structures.
 *
 * Unlike the generic @c marshal() in tpm_marshal.c which copies raw
 * bytes in native order, this module performs proper big-endian
 * serialisation field-by-field.  This is required for:
 *   - **Name computation**: Name = nameAlg || H(marshaled TPMT_PUBLIC)
 *   - **outPublic.size**: accurate wire-format size (no struct padding)
 *
 * Currently supports @c TPMT_PUBLIC with @c TPM_ALG_RSA.
 *
 * @see tpm_marshal.c     for the native-order generic helper.
 * @see tpm_object.c      for @ref PublicMarshalAndComputeName.
 * @see TPM 2.0 Part 2, Table 184 (TPMT_PUBLIC definition).
 * @see TPM 2.0 Part 4 (Supporting Routines — Marshaling).
 */

#include "hw/misc/s32k358_tpm.h"
#include "hw/misc/tpm_create_primary.h"
#include <string.h>

/* ---- Big-endian marshaling helpers (file-internal) -------------------- */

/**
 * @brief Marshal a 16-bit integer in big-endian order.
 *
 * @param[in]     value  Value to marshal.
 * @param[in,out] buf    Write cursor (advanced by 2 bytes).
 * @return Number of bytes written (always 2).
 */
static UINT16 marshal_uint16(UINT16 value, BYTE **buf) {
    (*buf)[0] = (BYTE)(value >> 8);
    (*buf)[1] = (BYTE)(value & 0xFF);
    *buf += 2;
    return 2;
}

/**
 * @brief Marshal a 32-bit integer in big-endian order.
 *
 * @param[in]     value  Value to marshal.
 * @param[in,out] buf    Write cursor (advanced by 4 bytes).
 * @return Number of bytes written (always 4).
 */
static UINT16 marshal_uint32(UINT32 value, BYTE **buf) {
    (*buf)[0] = (BYTE)(value >> 24);
    (*buf)[1] = (BYTE)(value >> 16);
    (*buf)[2] = (BYTE)(value >> 8);
    (*buf)[3] = (BYTE)(value & 0xFF);
    *buf += 4;
    return 4;
}

/**
 * @brief Marshal a TPM2B-style sized buffer (size + data) in big-endian.
 *
 * @param[in]     size  Buffer size.
 * @param[in]     data  Data bytes (may be @c NULL if @p size is 0).
 * @param[in,out] buf   Write cursor.
 * @return Total bytes written (2 + @p size).
 */
static UINT16 marshal_uint16_buffer(UINT16 size, const BYTE *data, BYTE **buf) {
    UINT16 total = marshal_uint16(size, buf);
    if (size > 0 && data != NULL) {
        memcpy(*buf, data, size);
        *buf += size;
    }
    return total + size;
}

/* ---- Public API ------------------------------------------------------ */

/* See tpm_create_primary.h for documentation. */
UINT16 TPMT_PUBLIC_Marshal(const TPMT_PUBLIC *publicArea, BYTE *buffer) {
    BYTE *ptr = buffer;
    UINT16 size = 0;

    if (publicArea == NULL || buffer == NULL) {
        return 0;
    }

    // type (TPMI_ALG_PUBLIC - 2 bytes)
    size += marshal_uint16(publicArea->type, &ptr);

    // nameAlg (TPMI_ALG_HASH - 2 bytes)
    size += marshal_uint16(publicArea->nameAlg, &ptr);

    // objectAttributes (TPMA_OBJECT - 4 bytes as bitfield)
    UINT32 attrs = 0;
    if (publicArea->objectAttributes.fixedTPM) attrs |= (1u << 1);
    if (publicArea->objectAttributes.stClear) attrs |= (1u << 2);
    if (publicArea->objectAttributes.fixedParent) attrs |= (1u << 4);
    if (publicArea->objectAttributes.sensitiveDataOrigin) attrs |= (1u << 5);
    if (publicArea->objectAttributes.userWithAuth) attrs |= (1u << 6);
    if (publicArea->objectAttributes.adminWithPolicy) attrs |= (1u << 7);
    if (publicArea->objectAttributes.noDA) attrs |= (1u << 10);
    if (publicArea->objectAttributes.encryptedDuplication) attrs |= (1u << 11);
    if (publicArea->objectAttributes.restricted) attrs |= (1u << 16);
    if (publicArea->objectAttributes.decrypt) attrs |= (1u << 17);
    if (publicArea->objectAttributes.sign_encrypt) attrs |= (1u << 18);
    size += marshal_uint32(attrs, &ptr);

    // authPolicy (TPM2B_DIGEST)
    size += marshal_uint16_buffer(publicArea->authPolicy.size,
                                   publicArea->authPolicy.buffer, &ptr);

    // parameters (union - handle based on type)
    if (publicArea->type == TPM_ALG_RSA) {
        // symmetric (TPMT_SYM_DEF_OBJECT)
        size += marshal_uint16(publicArea->parameters.rsaDetail.symmetric.algorithm, &ptr);
        if (publicArea->parameters.rsaDetail.symmetric.algorithm != TPM_ALG_NULL) {
            size += marshal_uint16(publicArea->parameters.rsaDetail.symmetric.keyBits.aes, &ptr);
            size += marshal_uint16(publicArea->parameters.rsaDetail.symmetric.mode.sym, &ptr);
        }

        // scheme (TPMT_RSA_SCHEME)
        size += marshal_uint16(publicArea->parameters.rsaDetail.scheme.scheme, &ptr);
        if (publicArea->parameters.rsaDetail.scheme.scheme != TPM_ALG_NULL) {
            size += marshal_uint16(publicArea->parameters.rsaDetail.scheme.details.anySig.hashAlg, &ptr);
        }

        // keyBits (TPMI_RSA_KEY_BITS - 2 bytes)
        size += marshal_uint16(publicArea->parameters.rsaDetail.keyBits, &ptr);

        // exponent (UINT32)
        size += marshal_uint32(publicArea->parameters.rsaDetail.exponent, &ptr);
    }
    // TODO: Add other algorithm types if needed (ECC, SymCipher, KeyedHash)

    // unique (union - handle based on type)
    if (publicArea->type == TPM_ALG_RSA) {
        size += marshal_uint16_buffer(publicArea->unique.rsa.size,
                                       publicArea->unique.rsa.buffer, &ptr);
    }

    return size;
}

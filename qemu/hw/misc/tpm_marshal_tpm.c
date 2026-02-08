/*
 * tpm_marshal_tpm.c – TPM-specific marshaling functions.
 *
 * This file contains proper big-endian field-by-field marshaling for TPM
 * structures that require cryptographic determinism (e.g., for Name computation).
 *
 * Reference: TPM 2.0 Part 4 (Supporting Routines) - Marshaling
 */

#include "hw/misc/s32k358_tpm.h"
#include "hw/misc/tpm_create_primary.h"
#include <string.h>

/* -----------------------------------------------------------------------
 * Big-endian marshaling helpers (static, internal only)
 * ----------------------------------------------------------------------- */

static UINT16 marshal_uint16(UINT16 value, BYTE **buf) {
    (*buf)[0] = (BYTE)(value >> 8);
    (*buf)[1] = (BYTE)(value & 0xFF);
    *buf += 2;
    return 2;
}

static UINT16 marshal_uint32(UINT32 value, BYTE **buf) {
    (*buf)[0] = (BYTE)(value >> 24);
    (*buf)[1] = (BYTE)(value >> 16);
    (*buf)[2] = (BYTE)(value >> 8);
    (*buf)[3] = (BYTE)(value & 0xFF);
    *buf += 4;
    return 4;
}

static UINT16 marshal_uint16_buffer(UINT16 size, const BYTE *data, BYTE **buf) {
    UINT16 total = marshal_uint16(size, buf);
    if (size > 0 && data != NULL) {
        memcpy(*buf, data, size);
        *buf += size;
    }
    return total + size;
}

/* -----------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */

/*
 * TPMT_PUBLIC_Marshal – Marshal TPMT_PUBLIC structure for Name computation.
 *
 * This function performs proper big-endian field-by-field marshaling of
 * TPMT_PUBLIC as required by TPM 2.0 spec. The marshaled data is used for:
 *   - Name computation: Name = nameAlg || H(marshaled TPMT_PUBLIC)
 *   - Setting outPublic.size field
 *
 * Unlike memcpy of the struct, this marshaling:
 *   - Uses big-endian byte order for multi-byte integers
 *   - Excludes struct padding
 *   - Is deterministic across compilers and platforms
 *
 * Returns: Actual marshaled size in bytes (no padding)
 *
 * Reference: TPM 2.0 Part 2, Table 184 (TPMT_PUBLIC definition)
 */
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

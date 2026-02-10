/*
 * tpm_marshal.c – Firmware-side TPM marshaling functions.
 *
 * Ported from qemu/hw/misc/tpm_marshal_tpm.c to produce byte-identical
 * output for Name computation.
 */

#include <stdint.h>
#include <string.h>
#include "tpm_marshal.h"
#include "tpm2_spec_protocol.h"

/* -------------------------------------------------------------------
 * Big-endian marshaling helpers
 * ------------------------------------------------------------------- */

static uint16_t marshal_uint16(uint16_t value, uint8_t **buf) {
    (*buf)[0] = (uint8_t)(value >> 8);
    (*buf)[1] = (uint8_t)(value & 0xFF);
    *buf += 2;
    return 2;
}

static uint16_t marshal_uint32(uint32_t value, uint8_t **buf) {
    (*buf)[0] = (uint8_t)(value >> 24);
    (*buf)[1] = (uint8_t)(value >> 16);
    (*buf)[2] = (uint8_t)(value >> 8);
    (*buf)[3] = (uint8_t)(value & 0xFF);
    *buf += 4;
    return 4;
}

static uint16_t marshal_uint16_buffer(uint16_t size, const uint8_t *data,
                                      uint8_t **buf) {
    uint16_t total = marshal_uint16(size, buf);
    if (size > 0 && data != NULL) {
        memcpy(*buf, data, size);
        *buf += size;
    }
    return total + size;
}

/* -------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------- */

uint16_t TPMT_PUBLIC_Marshal(const TPMT_PUBLIC *publicArea, uint8_t *buffer) {
    uint8_t *ptr = buffer;
    uint16_t size = 0;

    if (publicArea == NULL || buffer == NULL) {
        return 0;
    }

    /* type (TPMI_ALG_PUBLIC - 2 bytes) */
    size += marshal_uint16(publicArea->type, &ptr);

    /* nameAlg (TPMI_ALG_HASH - 2 bytes) */
    size += marshal_uint16(publicArea->nameAlg, &ptr);

    /* objectAttributes (TPMA_OBJECT - 4 bytes as bitfield) */
    uint32_t attrs = 0;
    if (publicArea->objectAttributes.fixedTPM)
        attrs |= (1u << 1);
    if (publicArea->objectAttributes.stClear)
        attrs |= (1u << 2);
    if (publicArea->objectAttributes.fixedParent)
        attrs |= (1u << 4);
    if (publicArea->objectAttributes.sensitiveDataOrigin)
        attrs |= (1u << 5);
    if (publicArea->objectAttributes.userWithAuth)
        attrs |= (1u << 6);
    if (publicArea->objectAttributes.adminWithPolicy)
        attrs |= (1u << 7);
    if (publicArea->objectAttributes.noDA)
        attrs |= (1u << 10);
    if (publicArea->objectAttributes.encryptedDuplication)
        attrs |= (1u << 11);
    if (publicArea->objectAttributes.restricted)
        attrs |= (1u << 16);
    if (publicArea->objectAttributes.decrypt)
        attrs |= (1u << 17);
    if (publicArea->objectAttributes.sign_encrypt)
        attrs |= (1u << 18);
    size += marshal_uint32(attrs, &ptr);

    /* authPolicy (TPM2B_DIGEST) */
    size += marshal_uint16_buffer(publicArea->authPolicy.size,
                                  publicArea->authPolicy.buffer, &ptr);

    /* parameters (union, keyed on type) */
    if (publicArea->type == TPM_ALG_RSA) {
        /* symmetric (TPMT_SYM_DEF_OBJECT) */
        size += marshal_uint16(
            publicArea->parameters.rsaDetail.symmetric.algorithm, &ptr);
        if (publicArea->parameters.rsaDetail.symmetric.algorithm !=
            TPM_ALG_NULL) {
            size += marshal_uint16(
                publicArea->parameters.rsaDetail.symmetric.keyBits.aes, &ptr);
            size += marshal_uint16(
                publicArea->parameters.rsaDetail.symmetric.mode.sym, &ptr);
        }

        /* scheme (TPMT_RSA_SCHEME) */
        size += marshal_uint16(publicArea->parameters.rsaDetail.scheme.scheme,
                               &ptr);
        if (publicArea->parameters.rsaDetail.scheme.scheme != TPM_ALG_NULL) {
            size += marshal_uint16(
                publicArea->parameters.rsaDetail.scheme.details.anySig.hashAlg,
                &ptr);
        }

        /* keyBits (TPMI_RSA_KEY_BITS - 2 bytes) */
        size += marshal_uint16(publicArea->parameters.rsaDetail.keyBits, &ptr);

        /* exponent (UINT32) */
        size += marshal_uint32(publicArea->parameters.rsaDetail.exponent, &ptr);
    }

    /* unique (union, keyed on type) */
    if (publicArea->type == TPM_ALG_RSA) {
        size += marshal_uint16_buffer(publicArea->unique.rsa.size,
                                      publicArea->unique.rsa.buffer, &ptr);
    }

    return size;
}

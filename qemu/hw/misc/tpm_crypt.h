/**
 * @file tpm_crypt.h
 * @brief Public API for the TPM cryptographic module.
 *
 * Declares RNG, SHA-256, RSA (simplified), AES, and PKCS#7 helpers
 * used by the TPM command handlers.  All implementations are native
 * (no external libraries), as required by Spec Section 3.2.
 *
 * @see tpm_crypt.c             for the implementations.
 * @see tpm_create_primary.h    for DRBG and object-creation helpers.
 */

#ifndef HW_MISC_TPM_CRYPT_H
#define HW_MISC_TPM_CRYPT_H

#include <stddef.h>
#include <stdint.h>
#include "hw/misc/tpm2_spec_protocol.h"

/* ---- Random Number Generation ---------------------------------------- */

/**
 * @brief Generate @p size pseudo-random bytes into @p buffer.
 *
 * @param[in]  size    Number of bytes to generate.
 * @param[out] buffer  Destination buffer.
 */
void CryptRandomGenerate(uint16_t size, uint8_t *buffer);

/* ---- SHA-256 --------------------------------------------------------- */

/**
 * @brief Compute a SHA-256 digest over @p data (FIPS 180-4).
 *
 * @param[in]  data      Input message.
 * @param[in]  dataSize  Message length in bytes.
 * @param[out] digest    32-byte output digest.
 */
void SHA256_Calculate(const uint8_t *data, size_t dataSize, uint8_t *digest);

/** @brief Run SHA-256 known-answer tests (logged via @c qemu_log). */
void test_sha256_implementation(void);

/* ---- RSA-PSS (simplified simulation) --------------------------------- */

/**
 * @brief Apply simplified PKCS#1-like padding to a hash digest.
 *
 * @param[in]  hash        Digest to embed.
 * @param[in]  hashSize    Digest length.
 * @param[out] padded      Padded output.
 * @param[in]  paddedSize  Total output length.
 */
void RSA_PSS_Pad(const uint8_t *hash, uint16_t hashSize, uint8_t *padded, uint16_t paddedSize);

/**
 * @brief XOR-based "private-key encryption" (self-inverse).
 *
 * @param[in]  input       Input data.
 * @param[in]  inputSize   Data length.
 * @param[in]  privateKey  Key material.
 * @param[in]  keySize     Key length.
 * @param[out] output      Output buffer.
 */
void RSA_Private_Encrypt(const uint8_t *input, uint16_t inputSize,
                         const uint8_t *privateKey, uint16_t keySize,
                         uint8_t *output);

/**
 * @brief Sign data with RSA-PSS-SHA256 (simplified).
 *
 * @param[in]  data        Data to sign.
 * @param[in]  dataSize    Data length.
 * @param[in]  privateKey  RSA private key.
 * @param[in]  keySize     Key length.
 * @param[out] signature   Output signature.
 */
void CryptSignRSA_PSS_SHA256(const uint8_t *data, uint16_t dataSize,
                             const uint8_t *privateKey, uint16_t keySize,
                             uint8_t *signature);

/**
 * @brief Verify an RSA-PSS-SHA256 signature (simplified).
 *
 * @param[in] data       Original data.
 * @param[in] dataSize   Data length.
 * @param[in] signature  Signature to verify.
 * @param[in] sigSize    Signature length.
 * @param[in] publicKey  RSA public key.
 * @param[in] keySize    Key length.
 * @return 1 if valid, 0 if invalid.
 */
uint8_t CryptVerifySignatureRSA_PSS_SHA256(const uint8_t *data, uint16_t dataSize,
                                           const uint8_t *signature, uint16_t sigSize,
                                           const uint8_t *publicKey, uint16_t keySize);

/* ---- RSA Encrypt / Decrypt (XOR-based simulation) -------------------- */

/** @brief Encrypt with the public key (XOR simulation). */
TPM_RC CryptRSAEncrypt(const uint8_t *data, uint16_t dataSize,
                        const uint8_t *key, uint16_t keySize, uint8_t *out);

/** @brief Decrypt with the private key (XOR simulation). */
TPM_RC CryptRSADecrypt(const uint8_t *data, uint16_t dataSize,
                        const uint8_t *key, uint16_t keySize, uint8_t *out);

/* ---- AES (ECB with PKCS#7) ------------------------------------------- */

/** @brief AES-ECB encrypt with PKCS#7 padding. */
TPM_RC CryptEncrypt(const uint8_t *data, uint16_t dataSize,
                    const uint8_t *key, uint16_t keySize,
                    uint8_t *encrypted);

/** @brief AES-ECB decrypt with PKCS#7 unpadding. */
TPM_RC CryptDecrypt(const uint8_t *encrypted, uint16_t dataSize,
                    const uint8_t *key, uint16_t keySize,
                    uint8_t *decrypted);

/* ---- AES mode wrappers (no padding) ---------------------------------- */

/** @brief AES-ECB encrypt (block-aligned input required). */
void TPM_AES_ECB_Encrypt(const uint8_t *in, size_t dataSize,
                         const uint8_t *key, uint16_t keySize,
                         uint8_t *out);

/** @brief AES-ECB decrypt (block-aligned input required). */
void TPM_AES_ECB_Decrypt(const uint8_t *in, size_t dataSize,
                         const uint8_t *key, uint16_t keySize,
                         uint8_t *out);

/** @brief AES-CBC encrypt. */
void TPM_AES_CBC_Encrypt(const uint8_t *in, size_t dataSize,
                         const uint8_t *key, uint16_t keySize,
                         const uint8_t *iv, uint8_t *out, uint8_t *ivOut);

/** @brief AES-CBC decrypt. */
void TPM_AES_CBC_Decrypt(const uint8_t *in, size_t dataSize,
                         const uint8_t *key, uint16_t keySize,
                         const uint8_t *iv, uint8_t *out, uint8_t *ivOut);

/** @brief AES-CFB encrypt. */
void TPM_AES_CFB_Encrypt(const uint8_t *in, size_t dataSize,
                         const uint8_t *key, uint16_t keySize,
                         const uint8_t *iv, uint8_t *out, uint8_t *ivOut);

/** @brief AES-CFB decrypt. */
void TPM_AES_CFB_Decrypt(const uint8_t *in, size_t dataSize,
                         const uint8_t *key, uint16_t keySize,
                         const uint8_t *iv, uint8_t *out, uint8_t *ivOut);

/** @brief AES-OFB process (encrypt and decrypt are identical). */
void TPM_AES_OFB_Process(const uint8_t *in, size_t dataSize,
                         const uint8_t *key, uint16_t keySize,
                         const uint8_t *iv, uint8_t *out, uint8_t *ivOut);

/** @brief AES-CTR process (encrypt and decrypt are identical). */
void TPM_AES_CTR_Process(const uint8_t *in, size_t dataSize,
                         const uint8_t *key, uint16_t keySize,
                         const uint8_t *iv, uint8_t *out, uint8_t *ivOut);

/* ---- PKCS#7 padding -------------------------------------------------- */

/** @brief Apply PKCS#7 padding (block = 16). */
uint16_t PKCS7_Pad(const uint8_t *data, uint16_t dataSize, uint8_t *out);

/** @brief Remove PKCS#7 padding; returns 0 on invalid padding. */
uint16_t PKCS7_Unpad(const uint8_t *data, uint16_t dataSize, uint8_t *out);

/*
 * The CreatePrimary support function declarations have been moved to
 * tpm_create_primary.h, organized by class.  Include that header for:
 *   FindEmptyObjectSlot, ObjectSetLoadedAttributes, MemorySet,
 *   CreateChecks, RcSafeAddToResult, AdjustAuthSize,
 *   HierarchyGetPrimarySeed, HierarchyNormalizeHandle, EntityGetHierarchy,
 *   DRBG_InstantiateSeeded, DRBG_Uninstantiate, DRBG_Generate,
 *   CryptCreateObject, PublicMarshalAndComputeName,
 *   FillInCreationData, TicketComputeCreation
 */
#include "hw/misc/tpm_create_primary.h"

#endif
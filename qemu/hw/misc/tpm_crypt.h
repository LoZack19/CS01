#ifndef HW_MISC_TPM_CRYPT_H
#define HW_MISC_TPM_CRYPT_H

#include <stddef.h>
#include <stdint.h>
#include "hw/misc/tpm2_spec_protocol.h"

/* Public cryptographic helper APIs used by TPM command handlers */

void CryptRandomGenerate(uint16_t size, uint8_t *buffer);

/* SHA-256 */
void SHA256_Calculate(const uint8_t *data, size_t dataSize, uint8_t *digest);
void test_sha256_implementation(void);

/* RSA-PSS (simplified simulation) */
void RSA_PSS_Pad(const uint8_t *hash, uint16_t hashSize, uint8_t *padded, uint16_t paddedSize);
void RSA_Private_Encrypt(const uint8_t *input, uint16_t inputSize,
                         const uint8_t *privateKey, uint16_t keySize,
                         uint8_t *output);
void CryptSignRSA_PSS_SHA256(const uint8_t *data, uint16_t dataSize,
                             const uint8_t *privateKey, uint16_t keySize,
                             uint8_t *signature);
uint8_t CryptVerifySignatureRSA_PSS_SHA256(const uint8_t *data, uint16_t dataSize,
                                           const uint8_t *signature, uint16_t sigSize,
                                           const uint8_t *publicKey, uint16_t keySize);

/* Simplified RSA encryption/decryption (XOR-based simulation) */
TPM_RC CryptRSAEncrypt(const uint8_t *data, uint16_t dataSize,
                        const uint8_t *key, uint16_t keySize, uint8_t *out);
TPM_RC CryptRSADecrypt(const uint8_t *data, uint16_t dataSize,
                        const uint8_t *key, uint16_t keySize, uint8_t *out);

/* AES helpers (ECB/CBC/CFB/OFB/CTR) and simple wrappers */
TPM_RC CryptEncrypt(const uint8_t *data, uint16_t dataSize,
                    const uint8_t *key, uint16_t keySize,
                    uint8_t *encrypted);
TPM_RC CryptDecrypt(const uint8_t *encrypted, uint16_t dataSize,
                    const uint8_t *key, uint16_t keySize,
                    uint8_t *decrypted);

/* AES mode wrappers without padding (lengths must be multiples per mode rules) */
void TPM_AES_ECB_Encrypt(const uint8_t *in, size_t dataSize,
                         const uint8_t *key, uint16_t keySize,
                         uint8_t *out);
void TPM_AES_ECB_Decrypt(const uint8_t *in, size_t dataSize,
                         const uint8_t *key, uint16_t keySize,
                         uint8_t *out);
void TPM_AES_CBC_Encrypt(const uint8_t *in, size_t dataSize,
                         const uint8_t *key, uint16_t keySize,
                         const uint8_t *iv, uint8_t *out, uint8_t *ivOut);
void TPM_AES_CBC_Decrypt(const uint8_t *in, size_t dataSize,
                         const uint8_t *key, uint16_t keySize,
                         const uint8_t *iv, uint8_t *out, uint8_t *ivOut);
void TPM_AES_CFB_Encrypt(const uint8_t *in, size_t dataSize,
                         const uint8_t *key, uint16_t keySize,
                         const uint8_t *iv, uint8_t *out, uint8_t *ivOut);
void TPM_AES_CFB_Decrypt(const uint8_t *in, size_t dataSize,
                         const uint8_t *key, uint16_t keySize,
                         const uint8_t *iv, uint8_t *out, uint8_t *ivOut);
void TPM_AES_OFB_Process(const uint8_t *in, size_t dataSize,
                         const uint8_t *key, uint16_t keySize,
                         const uint8_t *iv, uint8_t *out, uint8_t *ivOut);
void TPM_AES_CTR_Process(const uint8_t *in, size_t dataSize,
                         const uint8_t *key, uint16_t keySize,
                         const uint8_t *iv, uint8_t *out, uint8_t *ivOut);

/* PKCS#7 padding helpers */
uint16_t PKCS7_Pad(const uint8_t *data, uint16_t dataSize, uint8_t *out);
uint16_t PKCS7_Unpad(const uint8_t *data, uint16_t dataSize, uint8_t *out);

/* Forward declarations - include tpm2_spec_protocol.h for full definitions */
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
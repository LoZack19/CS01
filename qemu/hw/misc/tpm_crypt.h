#ifndef HW_MISC_TPM_CRYPT_H
#define HW_MISC_TPM_CRYPT_H

#include <stddef.h>
#include <stdint.h>

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

/* AES helpers (ECB/CBC/CFB/OFB/CTR) and simple wrappers */
void CryptEncrypt(const uint8_t *data, uint16_t dataSize,
                  const uint8_t *key, uint16_t keySize,
                  uint8_t *encrypted);
void CryptDecrypt(const uint8_t *encrypted, uint16_t dataSize,
                  const uint8_t *key, uint16_t keySize,
                  uint8_t *decrypted);

/* PKCS#7 padding helpers */
uint16_t PKCS7_Pad(const uint8_t *data, uint16_t dataSize, uint8_t *out);
uint16_t PKCS7_Unpad(const uint8_t *data, uint16_t dataSize, uint8_t *out);

#endif


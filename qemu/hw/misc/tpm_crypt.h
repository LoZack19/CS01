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
struct _OBJECT;
struct _TPMT_PUBLIC;
struct _TPMS_SENSITIVE_CREATE;
struct _TPML_PCR_SELECTION;
struct _TPM2B_DATA;
struct _TPM2B_DIGEST;
struct _TPMT_TK_CREATION;
struct _TPM2B_AUTH;
struct _RAND_STATE;
struct _TPM2B;
struct _TPM2B_SEED;
struct _TPM2B_NAME;

/* Type aliases using struct tags to avoid conflicts */
typedef struct _OBJECT OBJECT_DECL;
typedef struct _TPM2B TPM2B_DECL;
typedef struct _TPM2B_SEED TPM2B_SEED_DECL;
typedef struct _TPM2B_NAME TPM2B_NAME_DECL;
typedef struct _TPMT_PUBLIC TPMT_PUBLIC_DECL;
typedef struct _TPMS_SENSITIVE_CREATE TPMS_SENSITIVE_CREATE_DECL;
typedef struct _TPML_PCR_SELECTION TPML_PCR_SELECTION_DECL;
typedef struct _TPM2B_DATA TPM2B_DATA_DECL;
typedef struct _TPM2B_DIGEST TPM2B_DIGEST_DECL;
typedef struct _TPMT_TK_CREATION TPMT_TK_CREATION_DECL;
typedef struct _TPM2B_AUTH TPM2B_AUTH_DECL;
typedef struct _RAND_STATE RAND_STATE_DECL;
typedef uint32_t TPM_RC;
typedef uint32_t TPM_HANDLE;
typedef uint16_t TPMI_ALG_HASH;

/* Note: These functions use types defined in tpm2_spec_protocol.h 
 * Include s32k358_tpm.h before this header */

/* Object and memory management */
struct _OBJECT* FindEmptyObjectSlot(TPM_HANDLE* handle);
void ObjectSetLoadedAttributes(struct _OBJECT* object, TPM_HANDLE parentHandle);
void MemorySet(void* dest, int val, size_t size);

/* Validation and checking */
TPM_RC CreateChecks(struct _OBJECT* parentObject, TPM_HANDLE parentHandle, 
                   struct _TPMT_PUBLIC* publicArea, uint32_t sensitiveDataSize);
TPM_RC RcSafeAddToResult(TPM_RC result, TPM_RC modifier);
uint8_t AdjustAuthSize(struct _TPM2B_AUTH* auth, TPMI_ALG_HASH nameAlg);

/* Hierarchy management */
TPM_RC HierarchyGetPrimarySeed(TPM_HANDLE hierarchy, struct _TPM2B_SEED* seed);
TPM_HANDLE HierarchyNormalizeHandle(TPM_HANDLE handle);
TPM_HANDLE EntityGetHierarchy(TPM_HANDLE handle);

/* DRBG (Deterministic Random Bit Generator) */
TPM_RC DRBG_InstantiateSeeded(struct _RAND_STATE* state, struct _TPM2B_SEED* seed,
                              const char* label, struct _TPM2B* extra, struct _TPM2B* name);
void DRBG_Uninstantiate(struct _RAND_STATE* state);

/* Object creation */
TPM_RC CryptCreateObject(struct _OBJECT* object, struct _TPMS_SENSITIVE_CREATE* sensitive,
                        struct _RAND_STATE* rand);
struct _TPM2B* PublicMarshalAndComputeName(struct _TPMT_PUBLIC* publicArea, struct _TPM2B_NAME* name);

/* Creation data and tickets */
void FillInCreationData(TPM_HANDLE parentHandle, TPMI_ALG_HASH nameAlg,
                       struct _TPML_PCR_SELECTION* creationPCR, struct _TPM2B_DATA* outsideInfo,
                       void* creationData, struct _TPM2B_DIGEST* creationHash);
TPM_RC TicketComputeCreation(TPM_HANDLE hierarchy, struct _TPM2B_NAME* name,
                            struct _TPM2B_DIGEST* creationHash, struct _TPMT_TK_CREATION* ticket);

#endif


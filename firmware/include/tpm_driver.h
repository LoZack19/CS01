#ifndef TPM_DRIVER_H
#define TPM_DRIVER_H

/*
 * tpm_driver.h — Low-level TPM FIFO interface and command dispatch.
 *
 * Provides:
 *   - MMIO I/O primitives (send / receive bytes through FIFO)
 *   - Locality / status control helpers
 *   - Raw-command helpers (for negative tests)
 *   - Auth-session helpers
 *   - TPM2 command wrapper function declarations
 */

#include "tpm_platform.h"
#include "tpm2_spec_protocol.h"
#include "tpm_tests_config.h"

/* ---- I/O primitives ---------------------------------------------------- */

bool tpm_send_rdy(void);
bool tpm_receive_rdy(void);
void tpm_send(const void *data, size_t size);
void tpm_receive(void *data, size_t size);

/* ---- Control ----------------------------------------------------------- */

void tpm_wait_access(void);
void tpm_command_ready(void);
void tpm_go(void);

/* ---- Helpers ----------------------------------------------------------- */

size_t tpm_min_size(size_t a, size_t b);
void tpm_drain_bytes(size_t size);

/* ---- Raw command helpers (transport / error negative tests) ------------- */

#if defined(TPM_TEST_ENABLE_TRANSPORT_NEGATIVE) || \
    defined(TPM_TEST_ENABLE_ERROR_HANDLING)
tpm_rsp_header_t tpm_send_raw_command(uint16_t tag,
                                      uint32_t commandCode,
                                      const void *payload,
                                      size_t payload_size);

tpm_rsp_header_t tpm_send_raw_command_bad_size(uint16_t tag,
                                               uint32_t commandCode,
                                               uint32_t declared_size,
                                               const void *payload,
                                               size_t payload_size);
#endif

/* ---- Auth-session helpers ---------------------------------------------- */

#define AUTH_CMD_AREA_SIZE sizeof(TPMS_AUTH_COMMAND_AREA)
#define AUTH_RSP_AREA_SIZE sizeof(TPMS_AUTH_RESPONSE_AREA)

void tpm_send_auth_area(void);
void skip_auth_response_area(void);

/* ---- TPM2 command wrappers --------------------------------------------- */

#ifdef TPM_TEST_ENABLE_NV_DEFINE
TPM_RC TPM2_NV_DefineSpace(NV_DefineSpace_In *in);
#endif

#ifdef TPM_TEST_ENABLE_NV_WRITE_READ
TPM_RC TPM2_NV_Write(NV_Write_In *in);
TPM_RC TPM2_NV_Read(NV_Read_In *in, NV_Read_Out *out);
#endif

#ifdef TPM_TEST_ENABLE_SIGN
TPM_RC TPM2_Sign(Sign_In *in, Sign_Out *out);
#endif

#ifdef TPM_TEST_ENABLE_VERIFY_SIGNATURE
TPM_RC TPM2_VerifySignature(VerifySignature_In *in, VerifySignature_Out *out);
#endif

#ifdef TPM_TEST_ENABLE_HASH
TPM_RC TPM2_Hash(Hash_In *in, Hash_Out *out);
#endif

#ifdef TPM_TEST_ENABLE_ENCRYPT_DECRYPT2
TPM_RC TPM2_EncryptDecrypt2(EncryptDecrypt2_In *in, EncryptDecrypt2_Out *out);
#endif

#ifdef TPM_TEST_ENABLE_RSA_ENCRYPT_DECRYPT
TPM_RC TPM2_RSA_Encrypt(RSA_Encrypt_In *in, RSA_Encrypt_Out *out);
TPM_RC TPM2_RSA_Decrypt(RSA_Decrypt_In *in, RSA_Decrypt_Out *out);
#endif

#ifdef TPM_TEST_ENABLE_CREATEPRIMARY
TPM_RC TPM2_CreatePrimary(CreatePrimary_In *in, CreatePrimary_Out *out);
#endif

#ifdef TPM_TEST_ENABLE_CREATE
TPM_RC TPM2_Create(Create_In *in, Create_Out *out);
#endif

#ifdef TPM_TEST_ENABLE_LOAD
TPM_RC TPM2_Load(Load_In *in, Load_Out *out);
#endif

#ifdef TPM_TEST_ENABLE_READPUBLIC
TPM_RC TPM2_ReadPublic(ReadPublic_In *in, ReadPublic_Out *out);
#endif

#ifdef TPM_TEST_ENABLE_OBJECTCHANGEAUTH
TPM_RC TPM2_ObjectChangeAuth(ObjectChangeAuth_In *in,
                             ObjectChangeAuth_Out *out);
#endif

#endif /* TPM_DRIVER_H */

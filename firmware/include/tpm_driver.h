/**
 * @file tpm_driver.h
 * @brief Low-level TPM FIFO driver and command-wrapper declarations.
 *
 * Organises the firmware-to-TPM interface in four layers:
 *   1. **I/O primitives** — byte-by-byte MMIO send/receive with busy-wait.
 *   2. **Control** — locality request, command-ready, go.
 *   3. **Raw command helpers** — for transport and error negative tests.
 *   4. **TPM2 command wrappers** — type-safe, conditionally compiled
 *      per tpm_tests_config.h.
 *
 * All wrappers follow the pattern:
 *   header → input struct → [auth area] → Go → receive header → [skip auth] → output struct.
 *
 * @see tpm_platform.h  for MMIO registers and bitmasks.
 * @see tpm_driver.c    for the implementation (X-macro command instantiation).
 */

#ifndef TPM_DRIVER_H
#define TPM_DRIVER_H

#include "tpm_platform.h"
#include "tpm2_spec_protocol.h"
#include "tpm_tests_config.h"

/* ---- I/O primitives ---------------------------------------------------- */

/**
 * @brief Busy-wait until TPM_STS.EXPECT is set.
 *
 * Polls the TPM_STS register and returns once the TPM is ready
 * to accept more command data bytes.
 *
 * @return @c true if the EXPECT flag is set; @c false otherwise.
 */
bool tpm_send_rdy(void);

/**
 * @brief Busy-wait until TPM_STS.DATA_AVAIL is set.
 *
 * Polls the TPM_STS register and returns once response data is
 * available for reading.
 *
 * @return @c true if the DATA_AVAIL flag is set; @c false otherwise.
 */
bool tpm_receive_rdy(void);

/**
 * @brief Write @p size bytes to TPM_DATA_FIFO, one byte at a time.
 *
 * Busy-waits on TPM_STS.EXPECT before each byte.
 *
 * @param[in] data  Pointer to the source buffer (must not be NULL).
 * @param[in] size  Number of bytes to transmit.
 *
 * @pre Locality acquired via tpm_wait_access().
 * @pre TPM_STS.COMMAND_READY asserted via tpm_command_ready().
 */
void tpm_send(const void *data, size_t size);

/**
 * @brief Read @p size bytes from TPM_DATA_FIFO, one byte at a time.
 *
 * Busy-waits on TPM_STS.DATA_AVAIL before each byte.
 *
 * @param[out] data  Pointer to the destination buffer (must not be NULL).
 * @param[in]  size  Number of bytes to read.
 *
 * @pre tpm_go() has been called and the TPM is executing or has finished.
 */
void tpm_receive(void *data, size_t size);

/* ---- Control ----------------------------------------------------------- */

/**
 * @brief Request locality 0 and busy-wait until TPM_ACCESS.ACTIVE_LOCAL.
 *
 * Must be called once after power-on before any other TPM operation.
 * Writes TPM_ACCESS_REQUEST_USE and polls until the locality is granted.
 */
void tpm_wait_access(void);

/**
 * @brief Assert TPM_STS.COMMAND_READY to prepare for a new command.
 *
 * Transitions the TPM from idle to the command-reception state.
 * Must be called before the first tpm_send() of a command sequence.
 */
void tpm_command_ready(void);

/**
 * @brief Assert TPM_STS.GO to execute the current command.
 *
 * Tells the TPM that all command bytes have been written and
 * execution may begin. After this call, response data can be
 * read with tpm_receive().
 */
void tpm_go(void);

/* ---- Helpers ----------------------------------------------------------- */

/**
 * @brief Return the smaller of @p a and @p b.
 *
 * @param a  First value.
 * @param b  Second value.
 * @return   The minimum of @p a and @p b.
 */
size_t tpm_min_size(size_t a, size_t b);

/**
 * @brief Discard @p size bytes from the response FIFO.
 *
 * Reads and discards data in 16-byte chunks.  Used to drain
 * trailing response bytes that the caller does not need.
 *
 * @param size  Number of bytes to consume and discard.
 */
void tpm_drain_bytes(size_t size);

/* ---- Raw command helpers (transport / error negative tests) ------------- */

#if defined(TPM_TEST_ENABLE_TRANSPORT_NEGATIVE) || \
    defined(TPM_TEST_ENABLE_ERROR_HANDLING)

/**
 * @brief Send a well-formed raw command and return the response header.
 *
 * Used by negative tests to inject arbitrary tag/CC combinations.
 * Automatically drains any trailing response bytes.
 *
 * @param tag           Command tag (e.g. TPM_ST_NO_SESSIONS).
 * @param commandCode   TPM_CC command code.
 * @param payload       Optional extra payload after the header (may be NULL).
 * @param payload_size  Size in bytes of @p payload.
 * @return              The complete response header received from the TPM.
 */
tpm_rsp_header_t tpm_send_raw_command(uint16_t tag,
                                      uint32_t commandCode,
                                      const void *payload,
                                      size_t payload_size);

/**
 * @brief Send a raw command with a deliberately wrong commandSize field.
 *
 * @p declared_size is written into the header while @p payload_size
 * bytes of actual payload are transmitted — used to test §3.1 size validation.
 *
 * @param tag            Command tag.
 * @param commandCode    TPM_CC command code.
 * @param declared_size  Value written into the header's commandSize field.
 * @param payload        Optional extra payload (may be NULL).
 * @param payload_size   Actual number of payload bytes to transmit.
 * @return               The response header from the TPM.
 */
tpm_rsp_header_t tpm_send_raw_command_bad_size(uint16_t tag,
                                               uint32_t commandCode,
                                               uint32_t declared_size,
                                               const void *payload,
                                               size_t payload_size);
#endif

/* ---- Auth-session helpers ---------------------------------------------- */

/** @brief Size of the marshalled password-session command auth area. */
#define AUTH_CMD_AREA_SIZE sizeof(TPMS_AUTH_COMMAND_AREA)
/** @brief Size of the marshalled password-session response auth area. */
#define AUTH_RSP_AREA_SIZE sizeof(TPMS_AUTH_RESPONSE_AREA)

/**
 * @brief Send a default password-session auth area after the command params.
 *
 * Writes a marshalled TPMS_AUTH_COMMAND_AREA with TPM_RS_PW handle
 * and empty nonce/hmac.  Called between the input parameters and
 * tpm_go() for TPM_ST_SESSIONS commands.
 */
void tpm_send_auth_area(void);

/**
 * @brief Skip (discard) the auth response area before reading output params.
 *
 * Reads and discards AUTH_RSP_AREA_SIZE bytes from the response
 * FIFO.  Must be called after the response header for
 * TPM_ST_SESSIONS commands, before reading the output structure.
 */
void skip_auth_response_area(void);

/* ---- TPM2 command wrappers --------------------------------------------- */

/**
 * @brief Generate random bytes (TPM2_GetRandom).
 *
 * @param[in]  in   Input: number of random bytes requested.
 * @param[out] out  Output: buffer with the random bytes.
 * @return TPM_RC_SUCCESS or a TPM error code.
 */
TPM_RC TPM2_GetRandom(GetRandom_In *in, GetRandom_Out *out);

#ifdef TPM_TEST_ENABLE_STATE_MACHINE
/**
 * @brief Initialise the TPM (TPM2_Startup).
 *
 * @param[in] in  Input: startupType (TPM_SU_CLEAR or TPM_SU_STATE).
 * @return TPM_RC_SUCCESS or a TPM error code.
 */
TPM_RC TPM2_Startup(Startup_In *in);

/**
 * @brief Perform an orderly shutdown (TPM2_Shutdown).
 *
 * @param[in] in  Input: shutdownType (TPM_SU_CLEAR or TPM_SU_STATE).
 * @return TPM_RC_SUCCESS or a TPM error code.
 */
TPM_RC TPM2_Shutdown(Shutdown_In *in);

/**
 * @brief Execute TPM self-test (TPM2_SelfTest).
 *
 * @param[in] in  Input: fullTest flag (YES / NO).
 * @return TPM_RC_SUCCESS or a TPM error code.
 */
TPM_RC TPM2_SelfTest(SelfTest_In *in);

/**
 * @brief Query TPM capabilities (TPM2_GetCapability).
 *
 * @param[in]  in   Input: capability, property, propertyCount.
 * @param[out] out  Output: moreData flag and property value.
 * @return TPM_RC_SUCCESS or a TPM error code.
 */
TPM_RC TPM2_GetCapability(GetCapability_In *in, GetCapability_Out *out);

/**
 * @brief Read the result of the last self-test (TPM2_GetTestResult).
 *
 * @param[out] out  Output: test data and result code.
 * @return TPM_RC_SUCCESS or a TPM error code.
 */
TPM_RC TPM2_GetTestResult(GetTestResult_Out *out);

#ifdef TPM_TEST_ENABLE_NV_DEFINE
/**
 * @brief Define a new NV index (TPM2_NV_DefineSpace).
 *
 * @param[in] in  Input: authHandle, auth value, and NV public info.
 * @return TPM_RC_SUCCESS or a TPM error code.
 */
TPM_RC TPM2_NV_DefineSpace(NV_DefineSpace_In *in);
#endif

#ifdef TPM_TEST_ENABLE_NV_WRITE_READ
/**
 * @brief Write data to an NV index (TPM2_NV_Write).
 *
 * @param[in] in  Input: authHandle, nvIndex, data buffer, and offset.
 * @return TPM_RC_SUCCESS or a TPM error code.
 */
TPM_RC TPM2_NV_Write(NV_Write_In *in);

/**
 * @brief Read data from an NV index (TPM2_NV_Read).
 *
 * @param[in]  in   Input: authHandle, nvIndex, size, and offset.
 * @param[out] out  Output: data buffer.
 * @return TPM_RC_SUCCESS or a TPM error code.
 */
TPM_RC TPM2_NV_Read(NV_Read_In *in, NV_Read_Out *out);
#endif

#ifdef TPM_TEST_ENABLE_SIGN
/**
 * @brief Sign a digest with a loaded signing key (TPM2_Sign).
 *
 * @param[in]  in   Input: keyHandle, signing scheme, digest, validation.
 * @param[out] out  Output: TPMT_SIGNATURE containing the signature.
 * @return TPM_RC_SUCCESS or a TPM error code.
 */
TPM_RC TPM2_Sign(Sign_In *in, Sign_Out *out);
#endif

#ifdef TPM_TEST_ENABLE_VERIFY_SIGNATURE
/**
 * @brief Verify a signature against a loaded public key (TPM2_VerifySignature).
 *
 * @param[in]  in   Input: keyHandle, digest, and signature to verify.
 * @param[out] out  Output: validation ticket on success.
 * @return TPM_RC_SUCCESS or TPM_RC_SIGNATURE on verification failure.
 */
TPM_RC TPM2_VerifySignature(VerifySignature_In *in, VerifySignature_Out *out);
#endif

#ifdef TPM_TEST_ENABLE_HASH
/**
 * @brief Compute a hash of the supplied data (TPM2_Hash).
 *
 * @param[in]  in   Input: data buffer, hash algorithm, and hierarchy.
 * @param[out] out  Output: digest and validation ticket.
 * @return TPM_RC_SUCCESS or a TPM error code.
 */
TPM_RC TPM2_Hash(Hash_In *in, Hash_Out *out);
#endif

#ifdef TPM_TEST_ENABLE_ENCRYPT_DECRYPT2
/**
 * @brief Symmetric encrypt or decrypt (TPM2_EncryptDecrypt2).
 *
 * @param[in]  in   Input: keyHandle, direction, mode, IV, and data.
 * @param[out] out  Output: transformed data and output IV.
 * @return TPM_RC_SUCCESS or a TPM error code.
 */
TPM_RC TPM2_EncryptDecrypt2(EncryptDecrypt2_In *in, EncryptDecrypt2_Out *out);
#endif

#ifdef TPM_TEST_ENABLE_RSA_ENCRYPT_DECRYPT
/**
 * @brief RSA-OAEP encrypt a message (TPM2_RSA_Encrypt).
 *
 * @param[in]  in   Input: keyHandle and plaintext message.
 * @param[out] out  Output: ciphertext.
 * @return TPM_RC_SUCCESS or a TPM error code.
 */
TPM_RC TPM2_RSA_Encrypt(RSA_Encrypt_In *in, RSA_Encrypt_Out *out);

/**
 * @brief RSA-OAEP decrypt a ciphertext (TPM2_RSA_Decrypt).
 *
 * @param[in]  in   Input: keyHandle and ciphertext.
 * @param[out] out  Output: recovered plaintext.
 * @return TPM_RC_SUCCESS or a TPM error code.
 */
TPM_RC TPM2_RSA_Decrypt(RSA_Decrypt_In *in, RSA_Decrypt_Out *out);
#endif

#ifdef TPM_TEST_ENABLE_CREATEPRIMARY
/**
 * @brief Create a primary key under a hierarchy (TPM2_CreatePrimary).
 *
 * @param[in]  in   Input: hierarchy, sensitive data, public template,
 *                  outsideInfo, and PCR selection.
 * @param[out] out  Output: handle, public area, creation data, hash,
 *                  ticket, and Name of the new primary object.
 * @return TPM_RC_SUCCESS or a TPM error code.
 */
TPM_RC TPM2_CreatePrimary(CreatePrimary_In *in, CreatePrimary_Out *out);
#endif

#ifdef TPM_TEST_ENABLE_CREATE
/**
 * @brief Create a child key object (TPM2_Create).
 *
 * The created object is not automatically loaded—use TPM2_Load()
 * to obtain a transient handle.
 *
 * @param[in]  in   Input: parentHandle, sensitive data, public template,
 *                  outsideInfo, and PCR selection.
 * @param[out] out  Output: private blob, public area, creation metadata.
 * @return TPM_RC_SUCCESS or a TPM error code.
 */
TPM_RC TPM2_Create(Create_In *in, Create_Out *out);
#endif

#ifdef TPM_TEST_ENABLE_LOAD
/**
 * @brief Load a key created by TPM2_Create (TPM2_Load).
 *
 * Returns a transient handle in the 0x80xxxxxx range.
 *
 * @param[in]  in   Input: parentHandle, private blob, and public area.
 * @param[out] out  Output: transient objectHandle and Name.
 * @return TPM_RC_SUCCESS or a TPM error code.
 */
TPM_RC TPM2_Load(Load_In *in, Load_Out *out);
#endif

#ifdef TPM_TEST_ENABLE_READPUBLIC
/**
 * @brief Read the public area of a loaded object (TPM2_ReadPublic).
 *
 * @param[in]  in   Input: objectHandle to read.
 * @param[out] out  Output: public area, Name, and qualified Name.
 * @return TPM_RC_SUCCESS or a TPM error code.
 */
TPM_RC TPM2_ReadPublic(ReadPublic_In *in, ReadPublic_Out *out);
#endif

#ifdef TPM_TEST_ENABLE_OBJECTCHANGEAUTH
/**
 * @brief Change the auth value of an object (TPM2_ObjectChangeAuth).
 *
 * @param[in]  in   Input: objectHandle and new auth value.
 * @param[out] out  Output: updated private blob.
 * @return TPM_RC_SUCCESS or a TPM error code.
 */
TPM_RC TPM2_ObjectChangeAuth(ObjectChangeAuth_In *in,
                             ObjectChangeAuth_Out *out);
#endif

#endif /* TPM_DRIVER_H */

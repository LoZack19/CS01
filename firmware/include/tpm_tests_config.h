/**
 * @file tpm_tests_config.h
 * @brief Whitelist of enabled TPM test groups.
 *
 * Each \c \#define below enables a corresponding test function or group.
 * Comment out a line to skip that test at compile time.
 *
 * Groups are organised to match the verification-property sections
 * defined in @c docs/verification/verification.md (S.1–S.10).
 *
 * @see tpm_test_smoke.c   — smoke-level tests for individual commands
 * @see tpm_test_keymgmt.c — key lifecycle and verification-property tests
 */

#pragma once

/* ---- NV / Storage (§4.3 NV commands) ----------------------------------- */

// #define TPM_TEST_ENABLE_NV_DEFINE           /**< NV_DefineSpace test.  */
// #define TPM_TEST_ENABLE_NV_WRITE_READ       /**< NV_Write / NV_Read.  */

/* ---- Cryptographic commands (§4.4–§4.6) -------------------------------- */

#define TPM_TEST_ENABLE_HASH                   /**< TPM2_Hash smoke.              */
#define TPM_TEST_ENABLE_SIGN                   /**< TPM2_Sign smoke.              */
#define TPM_TEST_ENABLE_VERIFY_SIGNATURE       /**< TPM2_VerifySignature smoke.   */
#define TPM_TEST_ENABLE_ENCRYPT_DECRYPT2       /**< TPM2_EncryptDecrypt2 smoke.   */
#define TPM_TEST_ENABLE_RSA_ENCRYPT_DECRYPT    /**< TPM2_RSA_Encrypt/Decrypt.     */

/* ---- Key management commands (§5 Key Lifecycle) ------------------------ */

#define TPM_TEST_ENABLE_CREATEPRIMARY          /**< TPM2_CreatePrimary (storage root). */
#define TPM_TEST_ENABLE_CREATE                 /**< TPM2_Create (child key).           */
#define TPM_TEST_ENABLE_LOAD                   /**< TPM2_Load (import child).          */
#define TPM_TEST_ENABLE_READPUBLIC             /**< TPM2_ReadPublic (read-back).       */
// #define TPM_TEST_ENABLE_OBJECTCHANGEAUTH    /**< TPM2_ObjectChangeAuth.             */

/* ---- Verification-property tests (S.1–S.10) ---------------------------- */

#define TPM_TEST_ENABLE_STATE_MACHINE                /**< S.1  — Startup / Shutdown.     */
#define TPM_TEST_ENABLE_TRANSPORT_NEGATIVE           /**< S.2  — Bad tag / CC / size.     */
#define TPM_TEST_ENABLE_CREATEPRIMARY_TEMPLATE_MATCH /**< S.3  — Template echo.           */
#define TPM_TEST_ENABLE_CREATE_NEGATIVE              /**< S.4  — Create bad inputs.       */
#define TPM_TEST_ENABLE_LOAD_PRIVATE_INTEGRITY       /**< S.5  — Private blob integrity.  */
#define TPM_TEST_ENABLE_SIGN_INTEGRATION             /**< S.6  — Sign / Verify suite.     */
#define TPM_TEST_ENABLE_WORKFLOW_INTEGRATION         /**< S.8  — End-to-end workflow.     */
#define TPM_TEST_ENABLE_ERROR_HANDLING               /**< S.9  — Error-code validation.   */
#define TPM_TEST_ENABLE_DATA_SIZES                   /**< S.10 — Boundary / size checks.  */

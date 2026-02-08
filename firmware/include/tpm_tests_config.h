#pragma once

/*
 * TPM Test Configuration
 *
 * White-list mode: uncomment the macros below to ENABLE individual TPM test
 * functionalities. By default, all tests are disabled unless enabled here.
 */

/* NV / Storage tests */
// #define TPM_TEST_ENABLE_NV_DEFINE
// #define TPM_TEST_ENABLE_NV_WRITE_READ

/* Crypto tests */
#define TPM_TEST_ENABLE_HASH
#define TPM_TEST_ENABLE_SIGN
#define TPM_TEST_ENABLE_VERIFY_SIGNATURE
#define TPM_TEST_ENABLE_ENCRYPT_DECRYPT2
#define TPM_TEST_ENABLE_RSA_ENCRYPT_DECRYPT

/* Key management tests */
#define TPM_TEST_ENABLE_CREATEPRIMARY
#define TPM_TEST_ENABLE_CREATE
#define TPM_TEST_ENABLE_LOAD
// #define TPM_TEST_ENABLE_READPUBLIC
// #define TPM_TEST_ENABLE_OBJECTCHANGEAUTH

/*
 * tpm_test_smoke.c - Standalone command smoke tests (no shared state).
 *
 * Contains:
 *   - GROUP A: Transport & framing negative tests  (verification S.1)
 *   - NV DefineSpace / WriteRead tests
 *   - Hash smoke test
 *   - Sign smoke test
 *   - VerifySignature smoke test
 *   - EncryptDecrypt2 smoke test
 *   - RSA Encrypt/Decrypt smoke test
 *   - GROUP G: Error handling tests  (verification S.9)
 */

#include "tpm_platform.h"
#include "tpm_assert.h"
#include "tpm_driver.h"
#include "tpm2_spec_protocol.h"
#include "tpm_tests_config.h"

/* ===========================================================================
 * GROUP A: Transport & Framing Negative Tests  (verification S.1)
 * ===========================================================================
 */
#ifdef TPM_TEST_ENABLE_TRANSPORT_NEGATIVE
void TPM2_Transport_negative_tests(void) {
    DBG_PRINT("\n[TEST] Transport & framing negative tests\n");

    /* A1 - Invalid tag -> TPM_RC_BAD_TAG */
    {
        GetRandom_In payload = {.bytesRequested = 4};
        tpm_rsp_header_t rsp = tpm_send_raw_command(0xFFFF, TPM_CC_GetRandom,
                                                    &payload, sizeof(payload));
        assert(rsp.responseCode == TPM_RC_BAD_TAG,
               "Transport A1: invalid tag should return TPM_RC_BAD_TAG\n",
               string_from_TPM_RC(TPM_RC_BAD_TAG),
               string_from_TPM_RC(rsp.responseCode));
    }

    /* A2 - Unknown command code -> TPM_RC_COMMAND_CODE */
    {
        uint8_t dummy = 0;
        tpm_rsp_header_t rsp = tpm_send_raw_command(
            TPM_ST_NO_SESSIONS, 0xDEADBEEF, &dummy, sizeof(dummy));
        assert(rsp.responseCode == TPM_RC_COMMAND_CODE,
               "Transport A2: unknown CC should return TPM_RC_COMMAND_CODE\n",
               string_from_TPM_RC(TPM_RC_COMMAND_CODE),
               string_from_TPM_RC(rsp.responseCode));
    }

    /* A3 - Short commandSize -> TPM_RC_COMMAND_SIZE
     * Declare commandSize = header-only (no payload), but actually
     * send a Hash_In payload.  QEMU checks declared vs expected. */
    {
        Hash_In payload = {0};
        payload.hashAlg = TPM_ALG_SHA256;
        payload.data.size = 4;
        payload.data.buffer[0] = 'X';

        tpm_rsp_header_t rsp = tpm_send_raw_command_bad_size(
            TPM_ST_NO_SESSIONS, TPM_CC_Hash,
            (uint32_t)sizeof(tpm_cmd_header_t) + 1, /* too small */
            &payload, sizeof(payload));
        assert(rsp.responseCode == TPM_RC_COMMAND_SIZE,
               "Transport A3: short commandSize should return "
               "TPM_RC_COMMAND_SIZE\n",
               string_from_TPM_RC(TPM_RC_COMMAND_SIZE),
               string_from_TPM_RC(rsp.responseCode));
    }

    DBG_PRINT("[TEST] Transport negative tests: DONE\n");
}
#endif

/* ===========================================================================
 * NV Tests
 * ===========================================================================
 */

#ifdef TPM_TEST_ENABLE_NV_DEFINE
void TPM2_NV_DefineSpace_test(void) {
    TPM_RC res;

    NV_DefineSpace_In test_input = {
        .authHandle = TPM_RH_OWNER,
        .auth = {.size = 0, // No authorization value (password) required for
                            // this example
                 .buffer = {0}},
        .publicInfo = {
            .size = 0,
            .nvPublic =
                {
                    .nvIndex = 0x01500016, // A valid index in the allowed range
                    .nameAlg = TPM_ALG_NULL,
                    .attributes = {.OWNERREAD = 1, .OWNERWRITE = 1},
                    .dataSize = 32, // The size of the NV space in bytes
                    .authPolicy = {.size =
                                       0, // No policy required for this example
                                   .buffer = {0}},
                },
        }};

    res = TPM2_NV_DefineSpace(&test_input);
    assert(res == TPM_RC_SUCCESS, "TPM2_NV_DefineSpace failed",
           string_from_TPM_RC(TPM_RC_SUCCESS), string_from_TPM_RC(res));
}
#endif

#ifdef TPM_TEST_ENABLE_NV_WRITE_READ
void TPM2_NV_WriteRead_test(void) {
    TPM_RC res;

    // Use previously defined nv_index
    const TPMI_RH_NV_INDEX nv_index = 0x01500016;
    const UINT16 data_size = 32;

    // --- 1. Write Data to NV Memory ---
    TPM2B_MAX_NV_BUFFER write_data = {
        .size = data_size,
        .buffer = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                   0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                   0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                   0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F}};

    NV_Write_In write_input = {
        .authHandle = TPM_RH_OWNER, // Authorize as Owner
        .nvIndex = nv_index,        // The index to write to
        .data = write_data,         // The data to write
        .offset = 0                 // Write at the beginning
    };

    res = TPM2_NV_Write(&write_input);
    assert(res == TPM_RC_SUCCESS, "TPM2_NV_Write failed",
           string_from_TPM_RC(TPM_RC_SUCCESS), string_from_TPM_RC(res));

    // --- 2. Read Data from NV Memory ---
    NV_Read_In read_input = {
        .authHandle = TPM_RH_OWNER, // Authorize as Owner
        .nvIndex = nv_index,        // The index to read from
        .size = data_size,          // Number of bytes to read
        .offset = 0                 // Read from the beginning
    };

    NV_Read_Out read_output = {0};

    res = TPM2_NV_Read(&read_input, &read_output);
    assert(res == TPM_RC_SUCCESS, "TPM2_NV_Read failed",
           string_from_TPM_RC(TPM_RC_SUCCESS), string_from_TPM_RC(res));

    // --- 3. Compare Actual Data with Expected ---
    char expected_size_str[12];
    char actual_size_str[12];
    snprintf(expected_size_str, sizeof(expected_size_str), "%u",
             write_data.size);
    snprintf(actual_size_str, sizeof(actual_size_str), "%u",
             read_output.data.size);
    assert(read_output.data.size == write_data.size, "NV Read size mismatch",
           expected_size_str, actual_size_str);

    assert(memcmp(read_output.data.buffer, write_data.buffer,
                  write_data.size) == 0,
           "NV Read data mismatch", NULL, NULL);
}
#endif

/* ===========================================================================
 * Hash Smoke Test
 * ===========================================================================
 */

#ifdef TPM_TEST_ENABLE_HASH
void TPM2_Hash_smoke_test(void) {
    Hash_In in = {0};
    Hash_Out out = {0};
    in.hashAlg = TPM_ALG_SHA256;
    in.data.size = 4;
    in.data.buffer[0] = 'A';
    in.data.buffer[1] = 'B';
    in.data.buffer[2] = 'C';
    in.data.buffer[3] = 'D';

    TPM_RC res = TPM2_Hash(&in, &out);
    assert(res != TPM_RC_BAD_TAG, "TPM2_Hash bad tag", "!= TPM_RC_BAD_TAG",
           string_from_TPM_RC(res));
    assert(res != TPM_RC_COMMAND_SIZE, "TPM2_Hash command size",
           "!= TPM_RC_COMMAND_SIZE", string_from_TPM_RC(res));

    if (res == TPM_RC_SUCCESS) {
        assert(out.digest.size > 0, "TPM2_Hash digest size", "> 0", "0");
    }
}
#endif

/* ===========================================================================
 * Sign Smoke Test
 * ===========================================================================
 */

#ifdef TPM_TEST_ENABLE_SIGN
void TPM2_Sign_smoke_test(void) {
    Sign_In in = {0};
    Sign_Out out = {0};

    in.keyHandle = 0x80000000;
    in.inScheme.scheme = TPM_ALG_NULL;
    in.inScheme.hashAlg = TPM_ALG_NULL;

    in.digest.size = 4;
    in.digest.buffer[0] = 'A';
    in.digest.buffer[1] = 'B';
    in.digest.buffer[2] = 'C';
    in.digest.buffer[3] = 'D';

    TPM_RC res = TPM2_Sign(&in, &out);
    assert(res != TPM_RC_BAD_TAG, "TPM2_Sign bad tag", "!= TPM_RC_BAD_TAG",
           string_from_TPM_RC(res));
    assert(res != TPM_RC_COMMAND_SIZE, "TPM2_Sign command size",
           "!= TPM_RC_COMMAND_SIZE", string_from_TPM_RC(res));

    if (res == TPM_RC_SUCCESS) {
        assert(out.signature.signature.size > 0, "TPM2_Sign signature size",
               "> 0", "0");
    }
}
#endif

/* ===========================================================================
 * VerifySignature Smoke Test
 * ===========================================================================
 */

#ifdef TPM_TEST_ENABLE_VERIFY_SIGNATURE
void TPM2_VerifySignature_smoke_test(void) {
    VerifySignature_In in = {0};
    VerifySignature_Out out = {0};

    in.keyHandle = 0x80000000;

    in.digest.size = 4;
    in.digest.buffer[0] = 'A';
    in.digest.buffer[1] = 'B';
    in.digest.buffer[2] = 'C';
    in.digest.buffer[3] = 'D';

    in.signature.signature.size = TPM_MAX_SIGNATURE_SIZE;
    for (int i = 0; i < TPM_MAX_SIGNATURE_SIZE; i++) {
        in.signature.signature.buffer[i] = (uint8_t)(0xA5u ^ (uint8_t)i);
    }

    TPM_RC res = TPM2_VerifySignature(&in, &out);
    assert(res != TPM_RC_BAD_TAG, "TPM2_VerifySignature bad tag",
           "!= TPM_RC_BAD_TAG", string_from_TPM_RC(res));
    assert(res != TPM_RC_COMMAND_SIZE, "TPM2_VerifySignature command size",
           "!= TPM_RC_COMMAND_SIZE", string_from_TPM_RC(res));

    (void)out;
}
#endif

/* ===========================================================================
 * EncryptDecrypt2 Smoke Test
 * ===========================================================================
 */

#ifdef TPM_TEST_ENABLE_ENCRYPT_DECRYPT2
void TPM2_EncryptDecrypt2_smoke_test(void) {
    EncryptDecrypt2_In in = {0};
    EncryptDecrypt2_Out out = {0};

    in.keyHandle = 0x80000000;

    in.decrypt = 0;
    // Modified to match EncryptDecrypt2_In structure (no symDef, direct mode)
    in.mode = TPM_ALG_CBC;
    // Key bits/Alg determined by key handle

    in.ivIn.size = 16;
    for (int i = 0; i < 16; i++) {
        in.ivIn.buffer[i] = (uint8_t)i;
    }

    in.inData.size = 16;
    for (int i = 0; i < 16; i++) {
        in.inData.buffer[i] = (uint8_t)('A' + i);
    }

    TPM_RC res = TPM2_EncryptDecrypt2(&in, &out);
    assert(res != TPM_RC_BAD_TAG, "TPM2_EncryptDecrypt2 bad tag",
           "!= TPM_RC_BAD_TAG", string_from_TPM_RC(res));
    assert(res != TPM_RC_COMMAND_SIZE, "TPM2_EncryptDecrypt2 command size",
           "!= TPM_RC_COMMAND_SIZE", string_from_TPM_RC(res));

    if (res == TPM_RC_SUCCESS) {
        char expected_size_str[12];
        char actual_size_str[12];
        snprintf(expected_size_str, sizeof(expected_size_str), "%u",
                 in.inData.size);
        snprintf(actual_size_str, sizeof(actual_size_str), "%u",
                 out.outData.size);
        assert(out.outData.size == in.inData.size,
               "EncryptDecrypt2 size mismatch", expected_size_str,
               actual_size_str);
    }
}
#endif

/* ===========================================================================
 * RSA Encrypt/Decrypt Smoke Test
 * ===========================================================================
 */

#ifdef TPM_TEST_ENABLE_RSA_ENCRYPT_DECRYPT
void TPM2_RSA_EncryptDecrypt_smoke_test(void) {
    RSA_Encrypt_In enc_in = {0};
    RSA_Encrypt_Out enc_out = {0};

    enc_in.keyHandle = 0x80000000;
    enc_in.message.size = 4;
    enc_in.message.buffer[0] = 'A';
    enc_in.message.buffer[1] = 'B';
    enc_in.message.buffer[2] = 'C';
    enc_in.message.buffer[3] = 'D';

    TPM_RC res = TPM2_RSA_Encrypt(&enc_in, &enc_out);
    assert(res != TPM_RC_BAD_TAG, "TPM2_RSA_Encrypt bad tag",
           "!= TPM_RC_BAD_TAG", string_from_TPM_RC(res));
    assert(res != TPM_RC_COMMAND_SIZE, "TPM2_RSA_Encrypt command size",
           "!= TPM_RC_COMMAND_SIZE", string_from_TPM_RC(res));

    RSA_Decrypt_In dec_in = {0};
    RSA_Decrypt_Out dec_out = {0};

    dec_in.keyHandle = 0x80000000;
    dec_in.encrypted.size = 4;
    dec_in.encrypted.buffer[0] = 0x11;
    dec_in.encrypted.buffer[1] = 0x22;
    dec_in.encrypted.buffer[2] = 0x33;
    dec_in.encrypted.buffer[3] = 0x44;

    res = TPM2_RSA_Decrypt(&dec_in, &dec_out);
    assert(res != TPM_RC_BAD_TAG, "TPM2_RSA_Decrypt bad tag",
           "!= TPM_RC_BAD_TAG", string_from_TPM_RC(res));
    assert(res != TPM_RC_COMMAND_SIZE, "TPM2_RSA_Decrypt command size",
           "!= TPM_RC_COMMAND_SIZE", string_from_TPM_RC(res));

    (void)enc_out;
    (void)dec_out;
}
#endif

/* ===========================================================================
 * GROUP G: Error Handling Tests  (verification S.9)
 * ===========================================================================
 */

#ifdef TPM_TEST_ENABLE_ERROR_HANDLING
void TPM2_Error_handling_tests(void) {
    DBG_PRINT("\n[TEST] Error handling tests\n");

    /* G1 - TPM_RC_HANDLE for invalid handles: Load with bad parent */
#ifdef TPM_TEST_ENABLE_LOAD
    {
        Load_In bad_in = {0};
        Load_Out bad_out = {0};
        bad_in.parentHandle = 0xFFFFFFFF; /* invalid */
        bad_in.inPrivate.size = 1;        /* non-zero so we pass size check */
        bad_in.inPrivate.buffer[0] = 0xAA;

        TPM_RC res = TPM2_Load(&bad_in, &bad_out);
        assert(res != TPM_RC_SUCCESS,
               "Error G1: Load with invalid parent should fail\n",
               "!= TPM_RC_SUCCESS", string_from_TPM_RC(res));
        DBG_PRINTF("[TEST] Error G1 (bad handle): rc=0x%08lX (%s)\n",
                   (unsigned long)res, string_from_TPM_RC(res));
    }
#endif

    /* G2 - TPM_RC_VALUE / TPM_RC_HASH for empty data:
     *       Hash with data.size = 0 -> expect error */
#ifdef TPM_TEST_ENABLE_HASH
    {
        Hash_In in = {0};
        Hash_Out out = {0};
        in.hashAlg = TPM_ALG_SHA256;
        in.data.size = 0; /* empty -> should be rejected */

        TPM_RC res = TPM2_Hash(&in, &out);
        assert(res != TPM_RC_SUCCESS,
               "Error G2: Hash with empty data should fail\n",
               "!= TPM_RC_SUCCESS", string_from_TPM_RC(res));
        DBG_PRINTF("[TEST] Error G2 (empty hash data): rc=0x%08lX (%s)\n",
                   (unsigned long)res, string_from_TPM_RC(res));
    }
#endif

    DBG_PRINT("[TEST] Error handling tests: DONE\n");
}
#endif

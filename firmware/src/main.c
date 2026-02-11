#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include "S32K358.h"
#include "Lpuart_Uart_Ip.h"
#include "IntCtrl_Ip.h"
#include "FreeRTOS.h"
#include "sha256.h"
#include <stdio.h>
#include "tpm2_spec_protocol.h"
#include "tpm_tests_config.h"
#include "tpm_marshal.h"

#define LPUART_INSTANCE (3U) // Usare LPUART3

// Debug logging - set to 1 to enable verbose output
#define TPM_DEBUG 1

#if TPM_DEBUG
#define DBG_PRINT(msg)                                             \
    do {                                                           \
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)(msg), \
                                strlen(msg), portMAX_DELAY);       \
    } while (0)

#define DBG_PRINTF(fmt, ...)                                          \
    do {                                                              \
        char _dbg_buf[128];                                           \
        int _dbg_len =                                                \
            snprintf(_dbg_buf, sizeof(_dbg_buf), fmt, ##__VA_ARGS__); \
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)_dbg_buf, \
                                _dbg_len, portMAX_DELAY);             \
    } while (0)
#else
#define DBG_PRINT(msg)       ((void)0)
#define DBG_PRINTF(fmt, ...) ((void)0)
#endif

// MMIO Register Definitions
#define TPM_BASE 0x40000000

#define TPM_ACCESS \
    (*(volatile uint8_t *)(TPM_BASE + 0x0000)) // Used to request and check
                                               // access to the TPM
#define TPM_STS (*(volatile uint32_t *)(TPM_BASE + 0x0018)) // only 3 bytes used
#define TPM_DATA_FIFO                 \
    (*(volatile uint8_t *)(TPM_BASE + \
                           0x0024)) // The FIFO register for sending commands
                                    // and reading responses.

// Bitmask Constants
#define TPM_ACCESS_REQUEST_USE  0x02
#define TPM_ACCESS_ACTIVE_LOCAL 0x20

#define TPM_STS_COMMAND_READY 0x40
#define TPM_STS_GO            0x20
#define TPM_STS_DATA_AVAIL    0x10
#define TPM_STS_EXPECT        0x08

// TPM Utilities

const char *string_from_TPM_RC(TPM_RC rc) {
    switch (rc) {
    /*
     * Important: several TPM_RC_* macros in our header are *modifiers* or
     * *aliases* (e.g. TPM_RC_H, TPM_RC_P, TPM_RC_1, RC_VER1, TPM_RCS_*).
     * They intentionally share integer values and are not distinguishable
     * at runtime, so they must NOT appear as distinct switch labels.
     */
    case TPM_RC_SUCCESS:
        return "TPM_RC_SUCCESS";
    case TPM_RC_BAD_TAG:
        return "TPM_RC_BAD_TAG";

    /* Ver1 family (RC_VER1 is a base, not a standalone code) */
    case TPM_RC_FAILURE:
        return "TPM_RC_FAILURE";
    case TPM_RC_COMMAND_SIZE:
        return "TPM_RC_COMMAND_SIZE";
    case TPM_RC_COMMAND_CODE:
        return "TPM_RC_COMMAND_CODE";
    case TPM_RC_NV_RANGE:
        return "TPM_RC_NV_RANGE";
    case TPM_RC_NV_LOCKED:
        return "TPM_RC_NV_LOCKED";
    case TPM_RC_NV_AUTHORIZATION:
        return "TPM_RC_NV_AUTHORIZATION";
    case TPM_RC_NV_UNINITIALIZED:
        return "TPM_RC_NV_UNINITIALIZED";
    case TPM_RC_NV_SPACE:
        return "TPM_RC_NV_SPACE";
    case TPM_RC_NV_DEFINED:
        return "TPM_RC_NV_DEFINED";

    /* Format-1 style base codes */
    case TPM_RC_ATTRIBUTES:
        return "TPM_RC_ATTRIBUTES";
    case TPM_RC_HASH:
        return "TPM_RC_HASH";
    case TPM_RC_VALUE:
        return "TPM_RC_VALUE";
    case TPM_RC_HIERARCHY:
        return "TPM_RC_HIERARCHY";
    case TPM_RC_MODE:
        return "TPM_RC_MODE";
    case TPM_RC_HANDLE:
        return "TPM_RC_HANDLE";
    case TPM_RCS_SIZE:
        return "TPM_RCS_SIZE";
    case TPM_RC_SIGNATURE:
        return "TPM_RC_SIGNATURE";
    case TPM_RC_KEY:
        return "TPM_RC_KEY";
    case TPM_RC_KEY_SIZE:
        return "TPM_RC_KEY_SIZE";
    case TPM_RC_BINDING:
        return "TPM_RC_BINDING";
    case TPM_RC_SEQUENCE:
        return "TPM_RC_SEQUENCE";

    default:
        return "UNKNOWN_RC";
    }
}

int assert_count = 0;
int assert_failures = 0;

void assert(bool expression, const char *msg, const char *expected,
            const char *actual) {
    if (!expression) {
        if (msg != NULL) {
            Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)msg,
                                    strlen(msg), portMAX_DELAY);
        }

        // Expected: <exp>, got: <got>
        if (expected != NULL) {
            Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE,
                                    (uint8_t *)"Expected: ", 10, portMAX_DELAY);

            Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)expected,
                                    strlen(expected), portMAX_DELAY);
        }

        if (actual != NULL) {
            Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)", got: ", 7,
                                    portMAX_DELAY);

            Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)actual,
                                    strlen(actual), portMAX_DELAY);
        }

        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"\n", 1,
                                portMAX_DELAY);

        assert_failures++;
    }
    assert_count++;
}

void assert_report(void) {
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"Assert Report\n", 14,
                            portMAX_DELAY);

    char buffer[50];
    int len =
        snprintf(buffer, sizeof(buffer), "Total asserts: %d\n", assert_count);
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)buffer, len,
                            portMAX_DELAY);

    len = snprintf(buffer, sizeof(buffer), "Failed asserts: %d\n",
                   assert_failures);
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)buffer, len,
                            portMAX_DELAY);

    if (assert_failures == 0) {
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE,
                                (uint8_t *)"All tests passed!\n", 18,
                                portMAX_DELAY);
    } else {
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE,
                                (uint8_t *)"Some tests failed!\n", 19,
                                portMAX_DELAY);
    }
}

// TPM Interface

bool tpm_send_rdy(void) {
    return TPM_STS & TPM_STS_EXPECT;
}

bool tpm_receive_rdy(void) {
    return TPM_STS & TPM_STS_DATA_AVAIL;
}

/**
 * @brief Send data into TPM
 * @param[in] data Data to be sent into the TPM
 * @param[in] size Amount of data to be sent
 *
 * @note This could be made more efficient by using burstSize instead of waiting
 *       on every byte.
 */
void tpm_send(const void *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        while (!tpm_send_rdy())
            ;
        TPM_DATA_FIFO = ((uint8_t *)data)[i];
    }
}

/**
 * @brief Receive data from TPM
 * @param[out] data Storage for the received data
 * @param[in] size Amount of data to retrieve
 *
 * @note This could be made more efficient by using burstSize instead of waiting
 *       on every byte.
 */
void tpm_receive(void *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        while (!tpm_receive_rdy())
            ;
        ((uint8_t *)data)[i] = TPM_DATA_FIFO;
    }
}

/**
 * @brief Request TPM locality and busy wait until it's granted
 */
static inline void tpm_wait_access(void) {
    TPM_ACCESS = TPM_ACCESS_REQUEST_USE;
    while (!(TPM_ACCESS & TPM_ACCESS_ACTIVE_LOCAL))
        ;
}

/**
 * @brief Notify TPM that a command is about to be sent in
 */
static inline void tpm_command_ready(void) {
    TPM_STS |= TPM_STS_COMMAND_READY;
}

/**
 * @brief Start the execution of a command
 */
static inline void tpm_go(void) {
    TPM_STS |= TPM_STS_GO;
}

// TPM Commands

static inline size_t min_size(size_t a, size_t b) {
    return (a < b) ? a : b;
}

static void tpm_drain_bytes(size_t size) {
    uint8_t sink[16];
    while (size > 0) {
        size_t chunk = min_size(size, sizeof(sink));
        tpm_receive(sink, chunk);
        size -= chunk;
    }
}

/* ===========================================================================
 * TPM_ST_SESSIONS Helper Functions
 * ===========================================================================
 */

/* Authorization area sizes using the wire-format structs */
#define AUTH_CMD_AREA_SIZE sizeof(TPMS_AUTH_COMMAND_AREA)
#define AUTH_RSP_AREA_SIZE sizeof(TPMS_AUTH_RESPONSE_AREA)

/**
 * @brief Send empty password authorization area using __packed struct.
 */
static void tpm_send_auth_area(void) {
    TPMS_AUTH_COMMAND_AREA area = {
        .authSize = sizeof(TPMS_AUTH_COMMAND),
        .auth = {
            .sessionHandle = TPM_RS_PW,
            /* nonce, sessionAttributes, hmac: zero-init */
        }};
    tpm_send(&area, sizeof(area));
}

/**
 * @brief Skip authorization response area in TPM_ST_SESSIONS responses.
 */
static void skip_auth_response_area(void) {
    TPMS_AUTH_RESPONSE_AREA area;
    tpm_receive(&area, sizeof(area));
}

#ifndef TPM2_InOut
#define TPM2_InOut(F)                                                        \
    TPM_RC TPM2_##F(F##_In *in, F##_Out *out) {                              \
        tpm_rsp_header_t rsp;                                                \
                                                                             \
        tpm_cmd_header_t cmd = {.tag = TPM_ST_NO_SESSIONS,                   \
                                .commandSize = sizeof(cmd) + sizeof(*in),    \
                                .commandCode = TPM_CC_##F};                  \
                                                                             \
        DBG_PRINTF("[DBG] TPM2_" #F                                          \
                   ": Sending cmd (tag=0x%04X, size=%lu, code=0x%08lX)\n",   \
                   cmd.tag, (unsigned long)cmd.commandSize,                  \
                   (unsigned long)cmd.commandCode);                          \
                                                                             \
        tpm_command_ready();                                                 \
        tpm_send(&cmd, sizeof(cmd));                                         \
        tpm_send(in, sizeof(*in));                                           \
                                                                             \
        tpm_go();                                                            \
                                                                             \
        tpm_receive(&rsp, sizeof(rsp));                                      \
        DBG_PRINTF("[DBG] TPM2_" #F                                          \
                   ": Received rsp (tag=0x%04X, size=%lu, rc=0x%08lX)\n",    \
                   rsp.tag, (unsigned long)rsp.responseSize,                 \
                   (unsigned long)rsp.responseCode);                         \
                                                                             \
        size_t remaining = 0;                                                \
        if (rsp.responseSize >= sizeof(rsp) && rsp.responseSize <= 4096) {   \
            remaining = (size_t)rsp.responseSize - sizeof(rsp);              \
        }                                                                    \
        DBG_PRINTF("[DBG] TPM2_" #F ": remaining=%lu bytes\n",               \
                   (unsigned long)remaining);                                \
                                                                             \
        if (out != NULL) {                                                   \
            memset(out, 0, sizeof(*out));                                    \
        }                                                                    \
                                                                             \
        if (rsp.responseCode != TPM_RC_SUCCESS) {                            \
            DBG_PRINTF("[DBG] TPM2_" #F                                      \
                       ": Error response, draining %lu bytes\n",             \
                       (unsigned long)remaining);                            \
            tpm_drain_bytes(remaining);                                      \
            return rsp.responseCode;                                         \
        }                                                                    \
                                                                             \
        if (out != NULL) {                                                   \
            size_t to_read = min_size(remaining, sizeof(*out));              \
            DBG_PRINTF("[DBG] TPM2_" #F                                      \
                       ": Reading %lu bytes to out (out size=%lu)\n",        \
                       (unsigned long)to_read, (unsigned long)sizeof(*out)); \
            tpm_receive(out, to_read);                                       \
            tpm_drain_bytes(remaining - to_read);                            \
        } else {                                                             \
            tpm_drain_bytes(remaining);                                      \
        }                                                                    \
                                                                             \
        return rsp.responseCode;                                             \
    }
#endif

#ifndef TPM2_In
#define TPM2_In(F)                                                         \
    TPM_RC TPM2_##F(F##_In *in) {                                          \
        tpm_rsp_header_t rsp;                                              \
                                                                           \
        tpm_cmd_header_t cmd = {.tag = TPM_ST_NO_SESSIONS,                 \
                                .commandSize = sizeof(cmd) + sizeof(*in),  \
                                .commandCode = TPM_CC_##F};                \
                                                                           \
        DBG_PRINTF("[DBG] TPM2_" #F                                        \
                   ": Sending cmd (tag=0x%04X, size=%lu, code=0x%08lX)\n", \
                   cmd.tag, (unsigned long)cmd.commandSize,                \
                   (unsigned long)cmd.commandCode);                        \
                                                                           \
        tpm_command_ready();                                               \
        tpm_send(&cmd, sizeof(cmd));                                       \
        tpm_send(in, sizeof(*in));                                         \
                                                                           \
        tpm_go();                                                          \
                                                                           \
        tpm_receive(&rsp, sizeof(rsp));                                    \
        DBG_PRINTF("[DBG] TPM2_" #F                                        \
                   ": Received rsp (tag=0x%04X, size=%lu, rc=0x%08lX)\n",  \
                   rsp.tag, (unsigned long)rsp.responseSize,               \
                   (unsigned long)rsp.responseCode);                       \
                                                                           \
        size_t remaining = 0;                                              \
        if (rsp.responseSize >= sizeof(rsp) && rsp.responseSize <= 4096) { \
            remaining = (size_t)rsp.responseSize - sizeof(rsp);            \
        }                                                                  \
        tpm_drain_bytes(remaining);                                        \
                                                                           \
        return rsp.responseCode;                                           \
    }
#endif

#ifdef TPM_TEST_ENABLE_NV_DEFINE
TPM2_In(NV_DefineSpace);
#endif

#ifdef TPM_TEST_ENABLE_NV_WRITE_READ
TPM2_In(NV_Write);
TPM2_InOut(NV_Read);
#endif

#ifdef TPM_TEST_ENABLE_SIGN
TPM2_InOut(Sign)
#endif

#ifdef TPM_TEST_ENABLE_VERIFY_SIGNATURE
    TPM2_InOut(VerifySignature)
#endif

#ifdef TPM_TEST_ENABLE_HASH
        TPM2_InOut(Hash)
#endif

#ifdef TPM_TEST_ENABLE_ENCRYPT_DECRYPT2
            TPM2_InOut(EncryptDecrypt2)
#endif

#ifdef TPM_TEST_ENABLE_RSA_ENCRYPT_DECRYPT
                TPM2_InOut(RSA_Encrypt) TPM2_InOut(RSA_Decrypt)
#endif

/* Key Management Commands */
#ifdef TPM_TEST_ENABLE_CREATEPRIMARY
                    TPM2_InOut(CreatePrimary)
#endif

#ifdef TPM_TEST_ENABLE_CREATE
                        TPM2_InOut(Create)
#endif

#ifdef TPM_TEST_ENABLE_LOAD
                            TPM2_InOut(Load)
#endif

#ifdef TPM_TEST_ENABLE_READPUBLIC
                                TPM2_InOut(ReadPublic);
#endif

#ifdef TPM_TEST_ENABLE_OBJECTCHANGEAUTH
TPM2_InOut(ObjectChangeAuth);
#endif
// TPM Tests

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

#ifdef TPM_TEST_ENABLE_HASH
void TPM2_Hash_smoke_test(void) {
    Hash_In in = {0};
    Hash_Out out = {0};
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

#ifdef TPM_TEST_ENABLE_SIGN
void TPM2_Sign_smoke_test(void) {
    Sign_In in = {0};
    Sign_Out out = {0};

    in.keyHandle = 0x80000000;

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

/*
 * ===========================================================================
 * KEY MANAGEMENT TESTS
 * ===========================================================================
 *
 * Test suite for TPM2 Key Management commands:
 * - TPM2_CreatePrimary: Create a primary key in a hierarchy
 * - TPM2_Create: Create a new key object under a parent
 * - TPM2_Load: Load a key into the TPM
 * - TPM2_ReadPublic: Read public area of a loaded object
 * - TPM2_ObjectChangeAuth: Change authorization value of an object
 *
 * These tests use shared state to test the complete key lifecycle.
 * ===========================================================================
 */

/* Shared state for key management tests */
#ifdef TPM_TEST_ENABLE_CREATEPRIMARY
static CreatePrimary_Out
    g_create_primary_out; /* Output from TPM2_CreatePrimary */
#endif

#ifdef TPM_TEST_ENABLE_CREATE
static Create_Out g_create_out; /* Output from TPM2_Create */
#endif

#ifdef TPM_TEST_ENABLE_LOAD
static Load_Out g_load_out; /* Output from TPM2_Load */
#endif

static TPM_HANDLE g_parent_handle; /* Parent key handle (primary) */
static bool g_key_created = false; /* Flag: key was created successfully */
static bool g_key_loaded = false;  /* Flag: key was loaded successfully */

/**
 * @brief Test TPM2_CreatePrimary command
 *
 * PURPOSE: Verify that the TPM2_CreatePrimary command successfully creates
 *          a new primary key in the Owner hierarchy.
 *
 * PASS:
 *   - TPM_RC_SUCCESS returned
 *   - Name should match the expected value for the given template
 *   - Hash(creationData) == creationHash
 *   - creationTicket is valid
 *
 * FAIL:
 *   - Any TPM_RC other than SUCCESS
 *   - Name doesn't match expected value for template
 *   - Hash(creationData) != creationHash
 *   - Invalid creationTicket
 */
#ifdef TPM_TEST_ENABLE_CREATEPRIMARY
void TPM2_CreatePrimary_test(void) {
    // ----------------------------------------------------------------
    // 1. Prepare Data Structures
    // ----------------------------------------------------------------

    // A. The Hierarchy Auth (We need permission to use the Owner Hierarchy)
    // By default, Owner Auth is empty. We pass ESYS_TR_PASSWORD.

    // C. Sensitive Data (Input 3 - Password for NEW key)
    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0, // SAPI ignores this outer size on input usually, but good
                   // practice
        .sensitive = {.userAuth = {.size = 0}, // No password for the new key
                      .data = {.size = 0}}};

    // D. Public Template (Input 4 - The Key Definition)
    TPM2B_PUBLIC inPublic = {
        .size = 0, // SAPI will calculate this
        .publicArea = {
            .type = TPM_ALG_RSA,
            .nameAlg = TPM_ALG_SHA256,
            .objectAttributes = {.userWithAuth = 1,
                                 .restricted = 1,
                                 .decrypt = 1,
                                 .fixedTPM = 1,
                                 .fixedParent = 1,
                                 .sensitiveDataOrigin = 1},
            .authPolicy = {.size = 0},
            .parameters.rsaDetail = {.symmetric = {.algorithm = TPM_ALG_AES,
                                                   .keyBits.aes = 128,
                                                   .mode.sym = TPM_ALG_CFB},
                                     .scheme = {.scheme = TPM_ALG_NULL},
                                     .keyBits = 2048,
                                     .exponent = 0},
            .unique.rsa = {.size = 0}}};

    // D. Metadata structures (PCRs and outside info)
    TPM2B_DATA outsideInfo = {.size = 0};
    TPML_PCR_SELECTION creationPCR = {.count = 0};

    CreatePrimary_In in = {.primaryHandle = TPM_RH_OWNER, // Owner Hierarchy
                           .inSensitive = inSensitive,
                           .inPublic = inPublic,
                           .outsideInfo = outsideInfo,
                           .creationPCR = creationPCR};

    // ----------------------------------------------------------------
    // 2. Execute Command
    // ----------------------------------------------------------------

    TPM_RC res = TPM2_CreatePrimary(&in, &g_create_primary_out);

    // ----------------------------------------------------------------
    // 3. Validate Results
    // ----------------------------------------------------------------

    // ----------------------------------------------------------------
    // ASSERT TPM_RC_SUCCESS returned
    // ----------------------------------------------------------------

    assert(res == TPM_RC_SUCCESS, "TPM2_CreatePrimary failed",
           string_from_TPM_RC(TPM_RC_SUCCESS), string_from_TPM_RC(res));

    // ----------------------------------------------------------------
    // ASSERT Name should match the expected value for the given template
    // ----------------------------------------------------------------

    // Name = nameAlg_BE(2) || SHA256(marshaled TPMT_PUBLIC)

    // 1. Marshal the public area into canonical big-endian form
    uint8_t marshal_buf[sizeof(TPMT_PUBLIC)];
    uint16_t marshal_len = TPMT_PUBLIC_Marshal(
        &g_create_primary_out.outPublic.publicArea, marshal_buf);

    // 2. Hash the marshaled bytes
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, marshal_buf, marshal_len);
    uint8_t digest[32];
    SHA256_Final(digest, &ctx);

    // 3. Prepend NameAlg (00 0B) to get the final "Name"
    uint8_t expected_name[34];
    expected_name[0] =
        (uint8_t)(g_create_primary_out.outPublic.publicArea.nameAlg >> 8);
    expected_name[1] =
        (uint8_t)(g_create_primary_out.outPublic.publicArea.nameAlg & 0xFF);
    memcpy(&expected_name[2], digest, 32);

    // 4. Compare with TPM returned Name
    {
        char exp_s[8], act_s[8];
        snprintf(exp_s, sizeof(exp_s), "%u", (unsigned)sizeof(expected_name));
        snprintf(act_s, sizeof(act_s), "%u", g_create_primary_out.name.size);
        assert(g_create_primary_out.name.size == sizeof(expected_name),
               "TPM2_CreatePrimary Name size mismatch", exp_s, act_s);
    }
    assert(memcmp(g_create_primary_out.name.buffer, expected_name,
                  sizeof(expected_name)) == 0,
           "TPM2_CreatePrimary Name mismatch", NULL, NULL);

    // ----------------------------------------------------------------
    // ASSERT Hash(creationData) == creationHash
    // ----------------------------------------------------------------

    // 1. Hash the creationData returned by the TPM
    uint8_t calculated_creation_hash[32];
    SHA256_CTX creation_ctx;
    SHA256_Init(&creation_ctx);

    DBG_PRINTF("[DBG] CreatePrimary: creationData.size = %u\n",
               g_create_primary_out.creationData.size);
    DBG_PRINTF("[DBG] CreatePrimary: creationHash.size = %u\n",
               g_create_primary_out.creationHash.size);

    // We hash the buffer of creationData, which contains the marshaled
    // TPMS_CREATION_DATA
    SHA256_Update(&creation_ctx, g_create_primary_out.creationData.buffer,
                  g_create_primary_out.creationData.size);
    SHA256_Final(calculated_creation_hash, &creation_ctx);

    // 2. Compare calculated hash against the creationHash returned by the TPM
    {
        char exp_s[8], act_s[8];
        snprintf(exp_s, sizeof(exp_s), "32");
        snprintf(act_s, sizeof(act_s), "%u",
                 g_create_primary_out.creationHash.size);
        assert(g_create_primary_out.creationHash.size == 32,
               "TPM2_CreatePrimary creationHash size mismatch", exp_s, act_s);
    }

    assert(memcmp(g_create_primary_out.creationHash.buffer,
                  calculated_creation_hash, 32) == 0,
           "TPM2_CreatePrimary creationHash mismatch", NULL, NULL);

    // ----------------------------------------------------------------
    // ASSERT creationTicket is valid
    // ----------------------------------------------------------------

    // A valid ticket should have the tag TPM_ST_CREATION
    assert(g_create_primary_out.creationTicket.tag == TPM_ST_CREATION,
           "TPM2_CreatePrimary ticket tag invalid", "TPM_ST_CREATION", "OTHER");

    // The hierarchy in the ticket must match the hierarchy used to create the
    // object
    assert(g_create_primary_out.creationTicket.hierarchy == TPM_RH_OWNER,
           "TPM2_CreatePrimary ticket hierarchy mismatch", "TPM_RH_OWNER",
           "OTHER");

    // The digest in the ticket must be non-zero (it's the HMAC/Signature)
    assert(g_create_primary_out.creationTicket.digest.size > 0,
           "TPM2_CreatePrimary ticket digest is empty", NULL, NULL);
}
#endif

#ifdef TPM_TEST_ENABLE_CREATEPRIMARY
/**
 * @brief Test TPM2_CreatePrimary with TPM_ST_SESSIONS (spec compliance test)
 *
 * PURPOSE: Verify that the TPM2_CreatePrimary command works with
 *          TPM_ST_SESSIONS tag and password authorization.
 *
 * PASS:
 *   - TPM_RC_SUCCESS returned
 *   - Response tag is TPM_ST_SESSIONS (0x8002)
 *   - Object handle is in transient range (0x80XXXXXX)
 *   - Name is present and valid
 *
 * FAIL:
 *   - Any TPM_RC other than SUCCESS
 *   - Response tag is not TPM_ST_SESSIONS
 *   - Invalid object handle or name
 */
void TPM2_CreatePrimary_with_sessions_test(void) {
    DBG_PRINT("\n=== TPM2_CreatePrimary with TPM_ST_SESSIONS Test ===\n");

    /* ----------------------------------------------------------------
     * 1. Prepare Data Structures (same as regular CreatePrimary test)
     * ---------------------------------------------------------------- */

    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0, .sensitive = {.userAuth = {.size = 0}, .data = {.size = 0}}};

    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM_ALG_RSA,
            .nameAlg = TPM_ALG_SHA256,
            .objectAttributes = {.userWithAuth = 1,
                                 .restricted = 1,
                                 .decrypt = 1,
                                 .fixedTPM = 1,
                                 .fixedParent = 1,
                                 .sensitiveDataOrigin = 1},
            .authPolicy = {.size = 0},
            .parameters.rsaDetail = {.symmetric = {.algorithm = TPM_ALG_AES,
                                                   .keyBits.aes = 128,
                                                   .mode.sym = TPM_ALG_CFB},
                                     .scheme = {.scheme = TPM_ALG_NULL},
                                     .keyBits = 2048,
                                     .exponent = 0},
            .unique.rsa = {.size = 0}}};

    TPM2B_DATA outsideInfo = {.size = 0};
    TPML_PCR_SELECTION creationPCR = {.count = 0};

    CreatePrimary_In in = {.primaryHandle = TPM_RH_OWNER,
                           .inSensitive = inSensitive,
                           .inPublic = inPublic,
                           .outsideInfo = outsideInfo,
                           .creationPCR = creationPCR};

    CreatePrimary_Out out;
    memset(&out, 0, sizeof(out));

    /* ----------------------------------------------------------------
     * 2. Send Command with TPM_ST_SESSIONS
     * ---------------------------------------------------------------- */

    tpm_cmd_header_t cmd = {.tag = TPM_ST_SESSIONS,
                            .commandSize =
                                sizeof(cmd) + sizeof(in) + AUTH_CMD_AREA_SIZE,
                            .commandCode = TPM_CC_CreatePrimary};

    DBG_PRINTF("[DBG] TPM2_CreatePrimary_sessions: Sending cmd (tag=0x%04X, "
               "size=%lu, code=0x%08lX)\n",
               cmd.tag, (unsigned long)cmd.commandSize,
               (unsigned long)cmd.commandCode);

    tpm_command_ready();
    tpm_send(&cmd, sizeof(cmd));
    tpm_send(&in, sizeof(in));
    tpm_send_auth_area(); /* Send password session area */
    tpm_go();

    /* ----------------------------------------------------------------
     * 3. Receive Response
     * ---------------------------------------------------------------- */

    tpm_rsp_header_t rsp;
    tpm_receive(&rsp, sizeof(rsp));

    DBG_PRINTF("[DBG] TPM2_CreatePrimary_sessions: Received rsp (tag=0x%04X, "
               "size=%lu, rc=0x%08lX)\n",
               rsp.tag, (unsigned long)rsp.responseSize,
               (unsigned long)rsp.responseCode);

    /* ----------------------------------------------------------------
     * 4. Validate Response
     * ---------------------------------------------------------------- */

    /* ASSERT: Command succeeded */
    assert(rsp.responseCode == TPM_RC_SUCCESS,
           "TPM2_CreatePrimary with sessions failed",
           string_from_TPM_RC(TPM_RC_SUCCESS),
           string_from_TPM_RC(rsp.responseCode));

    if (rsp.responseCode != TPM_RC_SUCCESS) {
        /* Drain remaining bytes and return */
        size_t remaining = (rsp.responseSize > sizeof(rsp)) ?
                               (size_t)rsp.responseSize - sizeof(rsp) :
                               0;
        tpm_drain_bytes(remaining);
        return;
    }

    /* ASSERT: Response tag is TPM_ST_SESSIONS */
    {
        char exp_str[8], act_str[8];
        snprintf(exp_str, sizeof(exp_str), "0x%04X", TPM_ST_SESSIONS);
        snprintf(act_str, sizeof(act_str), "0x%04X", rsp.tag);
        assert(rsp.tag == TPM_ST_SESSIONS,
               "Expected TPM_ST_SESSIONS response tag", exp_str, act_str);
    }

    /* Skip auth response area */
    skip_auth_response_area();

    /* Read output */
    tpm_receive(&out, sizeof(out));

    /* Drain any remaining bytes */
    size_t remaining =
        (rsp.responseSize > sizeof(rsp) + AUTH_RSP_AREA_SIZE + sizeof(out)) ?
            (size_t)rsp.responseSize - sizeof(rsp) - AUTH_RSP_AREA_SIZE -
                sizeof(out) :
            0;
    tpm_drain_bytes(remaining);

    /* ----------------------------------------------------------------
     * 5. Validate Output
     * ---------------------------------------------------------------- */

    /* ASSERT: Object handle is in transient range */
    {
        uint8_t ht = (uint8_t)(out.objectHandle >> HR_SHIFT);
        char exp_str[16], act_str[16];
        snprintf(exp_str, sizeof(exp_str), "0x80");
        snprintf(act_str, sizeof(act_str), "0x%02X", ht);
        assert(ht == 0x80,
               "TPM2_CreatePrimary_sessions: handle not in transient range",
               exp_str, act_str);
    }

    /* ASSERT: Name is present */
    assert(out.name.size > 0, "TPM2_CreatePrimary_sessions: name is empty",
           "> 0", "0");

    DBG_PRINT("[TEST] TPM2_CreatePrimary with TPM_ST_SESSIONS: SUCCESS\n");
    DBG_PRINTF("  Object handle: 0x%08lX\n", (unsigned long)out.objectHandle);
    DBG_PRINTF("  Name size: %u\n", out.name.size);
}
#endif

/**
 * @brief Test TPM2_Create command
 *
 * PURPOSE: Verify that the TPM2_Create command successfully creates a new
 *          RSA signing key under the primary (storage) key created by
 *          TPM2_CreatePrimary.
 *
 * PASS:
 *   - TPM_RC_SUCCESS returned
 *   - outPrivate.size > 0 (encrypted private portion generated)
 *   - outPublic.size  > 0 (public portion generated)
 *   - Hash(creationData) == creationHash
 *   - creationTicket tag == TPM_ST_CREATION
 *
 * FAIL:
 *   - Any TPM_RC other than SUCCESS
 *   - TPM_RC_BAD_TAG or TPM_RC_COMMAND_SIZE (marshalling errors)
 *   - Empty outputs (size == 0)
 *   - creationHash mismatch
 */
#ifdef TPM_TEST_ENABLE_CREATE
void TPM2_Create_test(void) {
    TPM_RC res;

    DBG_PRINT("[TEST] TPM2_Create: Creating RSA signing key under primary\n");

    /* Use the primary key handle from TPM2_CreatePrimary test */
    g_parent_handle = g_create_primary_out.objectHandle;
    DBG_PRINTF("[TEST] TPM2_Create: parent handle = 0x%08lX\n",
               (unsigned long)g_parent_handle);

    Create_In in = {0};
    memset(&g_create_out, 0, sizeof(g_create_out));

    /* ---- Parent handle ---- */
    in.parentHandle = g_parent_handle;

    /* ---- Sensitive: empty auth & no injected data ---- */
    in.inSensitive.size = 0;
    in.inSensitive.sensitive.userAuth.size = 0;
    in.inSensitive.sensitive.data.size = 0;

    /* ---- Public template: RSA-2048 signing key (unrestricted) ---- */
    in.inPublic.size = 0; /* TPM/marshaller will compute */
    in.inPublic.publicArea.type = TPM_ALG_RSA;
    in.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;

    in.inPublic.publicArea.objectAttributes.fixedTPM = 1;
    in.inPublic.publicArea.objectAttributes.fixedParent = 1;
    in.inPublic.publicArea.objectAttributes.sensitiveDataOrigin = 1;
    in.inPublic.publicArea.objectAttributes.userWithAuth = 1;
    in.inPublic.publicArea.objectAttributes.sign_encrypt = 1;
    /* NOT restricted, NOT decrypt => unrestricted signing key */

    in.inPublic.publicArea.authPolicy.size = 0;

    /* No inner symmetric protection (signing key, not storage key) */
    in.inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm =
        TPM_ALG_NULL;
    in.inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_RSASSA;
    in.inPublic.publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg =
        TPM_ALG_SHA256;
    in.inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
    in.inPublic.publicArea.parameters.rsaDetail.exponent =
        0; /* default 65537 */

    in.inPublic.publicArea.unique.rsa.size = 0; /* TPM generates */

    /* ---- No outside info / PCR ---- */
    in.outsideInfo.size = 0;
    in.creationPCR.count = 0;

    /* ---- Execute command ---- */
    res = TPM2_Create(&in, &g_create_out);

    /* ---- Marshalling sanity ---- */
    assert(res != TPM_RC_BAD_TAG, "TPM2_Create failed: bad tag\n",
           "!= TPM_RC_BAD_TAG", string_from_TPM_RC(res));
    assert(res != TPM_RC_COMMAND_SIZE, "TPM2_Create failed: command size\n",
           "!= TPM_RC_COMMAND_SIZE", string_from_TPM_RC(res));

    /* ---- Result validation ---- */
    assert(res == TPM_RC_SUCCESS, "TPM2_Create: command failed\n",
           string_from_TPM_RC(TPM_RC_SUCCESS), string_from_TPM_RC(res));

    if (res == TPM_RC_SUCCESS) {
        g_key_created = true;

        /* Private portion must be present (encrypted blob) */
        assert(g_create_out.outPrivate.size > 0,
               "TPM2_Create: outPrivate is empty\n", "> 0", "0");

        /* Public portion must be present */
        assert(g_create_out.outPublic.size > 0,
               "TPM2_Create: outPublic is empty\n", "> 0", "0");

        /* ---- Hash(creationData) == creationHash ---- */
        uint8_t calc_hash[32];
        SHA256_CTX hash_ctx;
        SHA256_Init(&hash_ctx);
        SHA256_Update(&hash_ctx, g_create_out.creationData.buffer,
                      g_create_out.creationData.size);
        SHA256_Final(calc_hash, &hash_ctx);

        assert(g_create_out.creationHash.size == 32,
               "TPM2_Create: creationHash size != 32\n", "32", "other");
        assert(memcmp(g_create_out.creationHash.buffer, calc_hash, 32) == 0,
               "TPM2_Create: creationHash mismatch\n", NULL, NULL);

        /* ---- creationTicket tag ---- */
        assert(g_create_out.creationTicket.tag == TPM_ST_CREATION,
               "TPM2_Create: ticket tag invalid\n", "TPM_ST_CREATION", "OTHER");

        DBG_PRINTF(
            "[TEST] TPM2_Create: SUCCESS (private=%u, public=%u bytes)\n",
            g_create_out.outPrivate.size, g_create_out.outPublic.size);
    } else {
        DBG_PRINTF("[TEST] TPM2_Create: FAILED with rc=0x%08lX (%s)\n",
                   (unsigned long)res, string_from_TPM_RC(res));
    }
}
#endif

/**
 * @brief Test TPM2_Load command
 *
 * PURPOSE: Verify that a key created with TPM2_Create can be loaded
 *          into the TPM for use.
 *
 * PREREQUISITE: TPM2_Create_test must have passed (g_key_created == true)
 *
 * PASS:
 *   - TPM_RC_SUCCESS returned
 *   - objectHandle is in the transient range (0x80XXXXXX)
 *   - name.size > 0 (object name computed)
 *   - Name == nameAlg || Hash(publicArea)   (computed from outPublic)
 *
 * FAIL:
 *   - Any TPM_RC other than SUCCESS
 *   - Handle outside transient range
 *   - Empty name
 *   - Name mismatch with calculated value
 */
#ifdef TPM_TEST_ENABLE_LOAD
void TPM2_Load_test(void) {
    TPM_RC res;

    DBG_PRINT("[TEST] TPM2_Load: Loading created key into TPM\n");

    /* Skip if Create failed */
    if (!g_key_created) {
        DBG_PRINT("[TEST] TPM2_Load: SKIPPED (Create failed)\n");
        assert(false, "TPM2_Load: SKIPPED because Create failed\n",
               "g_key_created==true", "false");
        return;
    }

    Load_In in = {0};
    memset(&g_load_out, 0, sizeof(g_load_out));

    /* Use the parent handle from Create */
    in.parentHandle = g_parent_handle;

    /* Use the private/public portions from Create output */
    memcpy(&in.inPrivate, &g_create_out.outPrivate, sizeof(in.inPrivate));
    memcpy(&in.inPublic, &g_create_out.outPublic, sizeof(in.inPublic));

    DBG_PRINTF("[TEST] TPM2_Load: parent=0x%08lX, private=%u, public=%u\n",
               (unsigned long)in.parentHandle, in.inPrivate.size,
               in.inPublic.size);

    /* ---- Execute command ---- */
    res = TPM2_Load(&in, &g_load_out);

    /* ---- Marshalling sanity ---- */
    assert(res != TPM_RC_BAD_TAG, "TPM2_Load failed: bad tag\n",
           "!= TPM_RC_BAD_TAG", string_from_TPM_RC(res));
    assert(res != TPM_RC_COMMAND_SIZE, "TPM2_Load failed: command size\n",
           "!= TPM_RC_COMMAND_SIZE", string_from_TPM_RC(res));

    /* ---- Must succeed ---- */
    assert(res == TPM_RC_SUCCESS, "TPM2_Load: command failed\n",
           string_from_TPM_RC(TPM_RC_SUCCESS), string_from_TPM_RC(res));

    if (res != TPM_RC_SUCCESS) {
        DBG_PRINTF("[TEST] TPM2_Load: FAILED with rc=0x%08lX (%s)\n",
                   (unsigned long)res, string_from_TPM_RC(res));
        return;
    }

    g_key_loaded = true;

    /* ================================================================
     * ASSERT 1: objectHandle is in transient object range (0x80XXXXXX)
     * TPM_HT_TRANSIENT = 0x80, shifted by HR_SHIFT (24) => 0x80000000
     * ================================================================ */
    {
        uint8_t ht = (uint8_t)(g_load_out.objectHandle >> HR_SHIFT);
        char exp_str[16], act_str[16];
        snprintf(exp_str, sizeof(exp_str), "0x80");
        snprintf(act_str, sizeof(act_str), "0x%02X", ht);
        assert(ht == 0x80, "TPM2_Load: handle not in transient range\n",
               exp_str, act_str);
    }

    /* ================================================================
     * ASSERT 2: objectHandle != 0 and != TPM_RH_UNASSIGNED
     * ================================================================ */
    {
        char handle_str[16];
        snprintf(handle_str, sizeof(handle_str), "0x%08lX",
                 (unsigned long)g_load_out.objectHandle);
        assert(g_load_out.objectHandle != 0,
               "TPM2_Load: objectHandle is zero\n", "!= 0", handle_str);
        assert(g_load_out.objectHandle != TPM_RH_UNASSIGNED,
               "TPM2_Load: objectHandle is UNASSIGNED\n",
               "!= TPM_RH_UNASSIGNED", handle_str);
    }

    /* ================================================================
     * ASSERT 3: name.size > 0
     * ================================================================ */
    assert(g_load_out.name.size > 0, "TPM2_Load: name is empty\n", "> 0", "0");

    /* ================================================================
     * ASSERT 4: Name == nameAlg || Hash(TPMT_PUBLIC)
     *
     * The Name of a loaded object is computed as:
     *   Name = nameAlg (2 bytes, big-endian) || Hash_nameAlg(publicArea)
     *
     * QEMU uses proper big-endian marshaling of TPMT_PUBLIC.
     * We must do the same on the firmware side.
     * ================================================================ */
    {
        TPMT_PUBLIC *pub = &g_create_out.outPublic.publicArea;

        /* Marshal then hash */
        uint8_t load_marshal_buf[sizeof(TPMT_PUBLIC)];
        uint16_t load_marshal_len = TPMT_PUBLIC_Marshal(pub, load_marshal_buf);
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, load_marshal_buf, load_marshal_len);

        uint8_t load_digest[32];
        SHA256_Final(load_digest, &ctx);

        /* Build expected Name = nameAlg_BE || digest */
        uint8_t expected_name[34];
        expected_name[0] = (uint8_t)(pub->nameAlg >> 8);
        expected_name[1] = (uint8_t)(pub->nameAlg & 0xFF);
        memcpy(&expected_name[2], load_digest, 32);

        /* Compare sizes */
        {
            char exp_s[8], act_s[8];
            snprintf(exp_s, sizeof(exp_s), "%u",
                     (unsigned)sizeof(expected_name));
            snprintf(act_s, sizeof(act_s), "%u", g_load_out.name.size);
            assert(g_load_out.name.size == sizeof(expected_name),
                   "TPM2_Load: Name size mismatch\n", exp_s, act_s);
        }

        /* Compare content */
        assert(memcmp(g_load_out.name.buffer, expected_name,
                      sizeof(expected_name)) == 0,
               "TPM2_Load: Name content mismatch\n", NULL, NULL);
    }

    /* ================================================================
     * ASSERT 5: public area type matches what we requested
     * ================================================================ */
    assert(g_create_out.outPublic.publicArea.type == TPM_ALG_RSA,
           "TPM2_Load: loaded key type != RSA\n", "TPM_ALG_RSA", "OTHER");

    DBG_PRINTF("[TEST] TPM2_Load: SUCCESS (handle=0x%08lX, name_size=%u)\n",
               (unsigned long)g_load_out.objectHandle, g_load_out.name.size);
}

/**
 * @brief Negative tests for TPM2_Load
 *
 * PURPOSE: Verify that the TPM correctly rejects malformed Load inputs.
 *          Each sub-test copies valid Create output, corrupts one field,
 *          and asserts that TPM2_Load returns an appropriate error.
 *
 * PREREQUISITE: TPM2_Load_test must have passed (g_key_loaded == true)
 *
 * Properties verified:
 *   1B - Binding Validation (public/private mismatch)
 *   1A - Attribute Consistency (sign+encrypt both CLEAR)
 *   1A - Key Size Consistency (keyBits mismatch)
 *   1D - Zero-Length Private Area
 */
void TPM2_Load_negative_tests(void) {
    TPM_RC res;

    DBG_PRINT("\n[TEST] TPM2_Load negative tests\n");

    if (!g_key_loaded) {
        DBG_PRINT("[TEST] TPM2_Load negative: SKIPPED (Load not ready)\n");
        return;
    }

    /* ================================================================
     * 1B: Binding Validation — modify nameAlg in public area
     *
     * The inPrivate was encrypted for the original public template.
     * Changing nameAlg in inPublic creates a public/private mismatch.
     * Expected: non-success (typically TPM_RC_BINDING)
     * ================================================================ */
    {
        Load_In bad_in = {0};
        Load_Out bad_out = {0};
        bad_in.parentHandle = g_parent_handle;
        memcpy(&bad_in.inPrivate, &g_create_out.outPrivate,
               sizeof(bad_in.inPrivate));
        memcpy(&bad_in.inPublic, &g_create_out.outPublic,
               sizeof(bad_in.inPublic));

        /* Corrupt: change nameAlg from SHA256 to SHA1 */
        bad_in.inPublic.publicArea.nameAlg = TPM_ALG_SHA1;

        res = TPM2_Load(&bad_in, &bad_out);
        assert(res != TPM_RC_SUCCESS,
               "TPM2_Load negative (binding): should have failed\n",
               "!= TPM_RC_SUCCESS", string_from_TPM_RC(res));
        DBG_PRINTF("[TEST] TPM2_Load negative (binding): rc=0x%08lX (%s)\n",
                   (unsigned long)res, string_from_TPM_RC(res));
    }

    /* ================================================================
     * 1A: Attribute Consistency — clear both sign and decrypt
     *
     * For a non-keyedHash object, at least one of sign_encrypt or
     * decrypt must be SET. Clearing both should yield TPM_RC_ATTRIBUTES.
     * ================================================================ */
    {
        Load_In bad_in = {0};
        Load_Out bad_out = {0};
        bad_in.parentHandle = g_parent_handle;
        memcpy(&bad_in.inPrivate, &g_create_out.outPrivate,
               sizeof(bad_in.inPrivate));
        memcpy(&bad_in.inPublic, &g_create_out.outPublic,
               sizeof(bad_in.inPublic));

        /* Corrupt: clear both sign_encrypt and decrypt */
        bad_in.inPublic.publicArea.objectAttributes.sign_encrypt = 0;
        bad_in.inPublic.publicArea.objectAttributes.decrypt = 0;

        res = TPM2_Load(&bad_in, &bad_out);
        assert(res != TPM_RC_SUCCESS,
               "TPM2_Load negative (attributes): should have failed\n",
               "!= TPM_RC_SUCCESS", string_from_TPM_RC(res));
        DBG_PRINTF("[TEST] TPM2_Load negative (attributes): rc=0x%08lX (%s)\n",
                   (unsigned long)res, string_from_TPM_RC(res));
    }

    /* ================================================================
     * 1A: Key Size Consistency — change keyBits to wrong value
     *
     * The private portion was created for 2048-bit RSA. Claiming
     * 1024-bit in the public area should be rejected.
     * ================================================================ */
    {
        Load_In bad_in = {0};
        Load_Out bad_out = {0};
        bad_in.parentHandle = g_parent_handle;
        memcpy(&bad_in.inPrivate, &g_create_out.outPrivate,
               sizeof(bad_in.inPrivate));
        memcpy(&bad_in.inPublic, &g_create_out.outPublic,
               sizeof(bad_in.inPublic));

        /* Corrupt: change keyBits from 2048 to 1024 */
        bad_in.inPublic.publicArea.parameters.rsaDetail.keyBits = 1024;

        res = TPM2_Load(&bad_in, &bad_out);
        assert(res != TPM_RC_SUCCESS,
               "TPM2_Load negative (key size): should have failed\n",
               "!= TPM_RC_SUCCESS", string_from_TPM_RC(res));
        DBG_PRINTF("[TEST] TPM2_Load negative (key size): rc=0x%08lX (%s)\n",
                   (unsigned long)res, string_from_TPM_RC(res));
    }

    /* ================================================================
     * 1D: Zero-Length Private Area
     *
     * A Load with an empty private area should always fail.
     * ================================================================ */
    {
        Load_In bad_in = {0};
        Load_Out bad_out = {0};
        bad_in.parentHandle = g_parent_handle;
        memcpy(&bad_in.inPublic, &g_create_out.outPublic,
               sizeof(bad_in.inPublic));

        /* Corrupt: zero-length private */
        bad_in.inPrivate.size = 0;
        memset(bad_in.inPrivate.buffer, 0, sizeof(bad_in.inPrivate.buffer));

        res = TPM2_Load(&bad_in, &bad_out);
        assert(res != TPM_RC_SUCCESS,
               "TPM2_Load negative (zero private): should have failed\n",
               "!= TPM_RC_SUCCESS", string_from_TPM_RC(res));
        DBG_PRINTF(
            "[TEST] TPM2_Load negative (zero private): rc=0x%08lX (%s)\n",
            (unsigned long)res, string_from_TPM_RC(res));
    }

    DBG_PRINT("[TEST] TPM2_Load negative tests: DONE\n");
}
#endif

/**
 * @brief Test TPM2_ReadPublic command
 *
 * PURPOSE: Verify that the public area of a loaded key can be read
 *          and that the data is consistent with what was created.
 *
 * PREREQUISITE: TPM2_Load_test must have passed (g_key_loaded == true)
 *
 * PASS:
 *   - TPM_RC_SUCCESS returned
 *   - outPublic.dataSize > 0 (public area not empty)
 *   - name.size > 0 (name present)
 *   - qualifiedName.size > 0 (qualified name present)
 *
 * FAIL:
 *   - Any TPM_RC other than SUCCESS
 *   - Empty outputs
 */
#ifdef TPM_TEST_ENABLE_READPUBLIC
void TPM2_ReadPublic_test(void) {
    TPM_RC res;

    DBG_PRINT("[TEST] TPM2_ReadPublic: Reading public area of loaded key\n");

    /* Skip if Load failed */
    if (!g_key_loaded) {
        DBG_PRINT("[TEST] TPM2_ReadPublic: SKIPPED (Load failed)\n");
        return;
    }

    ReadPublic_In in = {0};
    ReadPublic_Out out = {0};

    /* Read the public area of the loaded object */
    in.objectHandle = g_load_out.objectHandle;

    res = TPM2_ReadPublic(&in, &out);

    /* Check for marshalling errors */
    assert(res != TPM_RC_BAD_TAG, "TPM2_ReadPublic failed: bad tag\n",
           "!= TPM_RC_BAD_TAG", string_from_TPM_RC(res));

    assert(res != TPM_RC_COMMAND_SIZE, "TPM2_ReadPublic failed: command size\n",
           "!= TPM_RC_COMMAND_SIZE", string_from_TPM_RC(res));

    if (res == TPM_RC_SUCCESS) {
        /* Verify public area is present */
        assert(out.outPublic.size > 0, "TPM2_ReadPublic: outPublic is empty\n",
               "> 0", "0");

        /* Verify name is present */
        assert(out.name.size > 0, "TPM2_ReadPublic: name is empty\n", "> 0",
               "0");

        /* Verify qualified name is present */
        assert(out.qualifiedName.size > 0,
               "TPM2_ReadPublic: qualifiedName is empty\n", "> 0", "0");

        /* Verify name matches what was returned by Load */
        assert(out.name.size == g_load_out.name.size,
               "TPM2_ReadPublic: name size mismatch with Load output\n", NULL,
               NULL);

        if (out.name.size == g_load_out.name.size) {
            assert(memcmp(out.name.buffer, g_load_out.name.buffer,
                          out.name.size) == 0,
                   "TPM2_ReadPublic: name content mismatch with Load output\n",
                   NULL, NULL);
        }

        /* ================================================================
         * Property 2A: Public Area Match
         *
         * outPublic from ReadPublic must match the public area that was
         * originally created (g_create_out.outPublic). We marshal both
         * TPMT_PUBLIC structures to canonical form and compare bytes.
         * ================================================================ */
        {
            uint8_t rp_marshal[sizeof(TPMT_PUBLIC)];
            uint8_t cr_marshal[sizeof(TPMT_PUBLIC)];
            uint16_t rp_len =
                TPMT_PUBLIC_Marshal(&out.outPublic.publicArea, rp_marshal);
            uint16_t cr_len = TPMT_PUBLIC_Marshal(
                &g_create_out.outPublic.publicArea, cr_marshal);

            char exp_s[8], act_s[8];
            snprintf(exp_s, sizeof(exp_s), "%u", cr_len);
            snprintf(act_s, sizeof(act_s), "%u", rp_len);
            assert(rp_len == cr_len,
                   "TPM2_ReadPublic: public area marshaled size mismatch\n",
                   exp_s, act_s);

            if (rp_len == cr_len) {
                assert(memcmp(rp_marshal, cr_marshal, rp_len) == 0,
                       "TPM2_ReadPublic: public area content mismatch "
                       "with Create output\n",
                       NULL, NULL);
            }
        }

        /* ================================================================
         * Property 2D: Qualified Name Verification
         *
         * The qualified name must start with nameAlg (2 bytes, BE) and
         * be at least nameAlg_size + hash_size bytes long.
         * For SHA-256: >= 2 + 32 = 34 bytes.
         * ================================================================ */
        {
            char exp_s[8], act_s[8];
            snprintf(exp_s, sizeof(exp_s), ">= 34");
            snprintf(act_s, sizeof(act_s), "%u", out.qualifiedName.size);
            assert(out.qualifiedName.size >= 34,
                   "TPM2_ReadPublic: qualifiedName too short for SHA-256\n",
                   exp_s, act_s);

            /* First 2 bytes should be nameAlg in big-endian */
            uint8_t expected_alg_hi = (uint8_t)(TPM_ALG_SHA256 >> 8);
            uint8_t expected_alg_lo = (uint8_t)(TPM_ALG_SHA256 & 0xFF);
            char exp_alg[8], act_alg[8];
            snprintf(exp_alg, sizeof(exp_alg), "0x%02X%02X", expected_alg_hi,
                     expected_alg_lo);
            snprintf(act_alg, sizeof(act_alg), "0x%02X%02X",
                     out.qualifiedName.buffer[0], out.qualifiedName.buffer[1]);
            assert(out.qualifiedName.buffer[0] == expected_alg_hi &&
                       out.qualifiedName.buffer[1] == expected_alg_lo,
                   "TPM2_ReadPublic: qualifiedName nameAlg mismatch\n", exp_alg,
                   act_alg);
        }

        DBG_PRINTF("[TEST] TPM2_ReadPublic: SUCCESS (public=%u, name=%u, "
                   "qname=%u bytes)\n",
                   out.outPublic.size, out.name.size, out.qualifiedName.size);
    } else {
        DBG_PRINTF("[TEST] TPM2_ReadPublic: FAILED with rc=0x%08lX (%s)\n",
                   (unsigned long)res, string_from_TPM_RC(res));

        assert(res == TPM_RC_SUCCESS, "TPM2_ReadPublic: command failed\n",
               string_from_TPM_RC(TPM_RC_SUCCESS), string_from_TPM_RC(res));
    }
}
#endif

/**
 * @brief Test TPM2_ObjectChangeAuth command
 *
 * PURPOSE: Verify that the authorization value of an object can be
 *          changed correctly.
 *
 * PREREQUISITE: TPM2_Load_test must have passed (g_key_loaded == true)
 *
 * PASS:
 *   - TPM_RC_SUCCESS returned
 *   - outPrivate.dataSize > 0 (new private portion generated)
 *   - The new private portion differs from the original (auth changed)
 *
 * FAIL:
 *   - Any TPM_RC other than SUCCESS
 *   - Empty output
 */
#ifdef TPM_TEST_ENABLE_OBJECTCHANGEAUTH
void TPM2_ObjectChangeAuth_test(void) {
    TPM_RC res;

    DBG_PRINT(
        "[TEST] TPM2_ObjectChangeAuth: Changing auth value of loaded key\n");

    /* Skip if Load failed */
    if (!g_key_loaded) {
        DBG_PRINT("[TEST] TPM2_ObjectChangeAuth: SKIPPED (Load failed)\n");
        return;
    }

    ObjectChangeAuth_In in = {0};
    ObjectChangeAuth_Out out = {0};

    /* Configure input */
    in.objectHandle = g_load_out.objectHandle;
    in.parentHandle = g_parent_handle;

    /* New auth value - simple test value */
    in.newAuth.size = 8;
    in.newAuth.buffer[0] = 'N';
    in.newAuth.buffer[1] = 'E';
    in.newAuth.buffer[2] = 'W';
    in.newAuth.buffer[3] = 'A';
    in.newAuth.buffer[4] = 'U';
    in.newAuth.buffer[5] = 'T';
    in.newAuth.buffer[6] = 'H';
    in.newAuth.buffer[7] = '!';

    res = TPM2_ObjectChangeAuth(&in, &out);

    /* Check for marshalling errors */
    assert(res != TPM_RC_BAD_TAG, "TPM2_ObjectChangeAuth failed: bad tag\n",
           "!= TPM_RC_BAD_TAG", string_from_TPM_RC(res));

    assert(res != TPM_RC_COMMAND_SIZE,
           "TPM2_ObjectChangeAuth failed: command size\n",
           "!= TPM_RC_COMMAND_SIZE", string_from_TPM_RC(res));

    if (res == TPM_RC_SUCCESS) {
        /* Verify new private portion is present */
        assert(out.outPrivate.size > 0,
               "TPM2_ObjectChangeAuth: outPrivate is empty\n", "> 0", "0");

        /* Verify the new private portion is different from original
         * (this confirms the auth was actually changed) */
        bool is_different =
            (out.outPrivate.size != g_create_out.outPrivate.size);
        if (!is_different && out.outPrivate.size > 0) {
            is_different =
                (memcmp(out.outPrivate.buffer, g_create_out.outPrivate.buffer,
                        out.outPrivate.size) != 0);
        }

        assert(is_different,
               "TPM2_ObjectChangeAuth: outPrivate unchanged (auth may not have "
               "changed)\n",
               "different", "same");

        DBG_PRINTF(
            "[TEST] TPM2_ObjectChangeAuth: SUCCESS (new_private=%u bytes)\n",
            out.outPrivate.size);
    } else {
        DBG_PRINTF(
            "[TEST] TPM2_ObjectChangeAuth: FAILED with rc=0x%08lX (%s)\n",
            (unsigned long)res, string_from_TPM_RC(res));

        assert(res == TPM_RC_SUCCESS, "TPM2_ObjectChangeAuth: command failed\n",
               string_from_TPM_RC(TPM_RC_SUCCESS), string_from_TPM_RC(res));
    }
}
#endif

/**
 * @brief Run all key management tests in sequence
 *
 * Tests are run in order because they share state:
 * CreatePrimary -> Create -> Load -> ReadPublic -> ObjectChangeAuth
 */
void TPM2_KeyManagement_test_suite(void) {
    DBG_PRINT("\n");
    DBG_PRINT("==================================================\n");
    DBG_PRINT("[SUITE] Key Management Tests\n");
    DBG_PRINT("==================================================\n");

    /* Reset shared state */
    g_key_created = false;
    g_key_loaded = false;
#ifdef TPM_TEST_ENABLE_CREATEPRIMARY
    memset(&g_create_primary_out, 0, sizeof(g_create_primary_out));
#endif
#ifdef TPM_TEST_ENABLE_CREATE
    memset(&g_create_out, 0, sizeof(g_create_out));
#endif
#ifdef TPM_TEST_ENABLE_LOAD
    memset(&g_load_out, 0, sizeof(g_load_out));
#endif

    /* Run tests in sequence */
#ifdef TPM_TEST_ENABLE_CREATEPRIMARY
    TPM2_CreatePrimary_test();
    TPM2_CreatePrimary_with_sessions_test();
#else
    DBG_PRINT("[TEST] TPM2_CreatePrimary: SKIPPED (not enabled)\n");
#endif

#if defined(TPM_TEST_ENABLE_CREATE) && defined(TPM_TEST_ENABLE_CREATEPRIMARY)
    TPM2_Create_test();
#elif defined(TPM_TEST_ENABLE_CREATE)
    DBG_PRINT("[TEST] TPM2_Create: SKIPPED (CreatePrimary not enabled)\n");
#endif

#if defined(TPM_TEST_ENABLE_LOAD) && defined(TPM_TEST_ENABLE_CREATE)
    TPM2_Load_test();
    TPM2_Load_negative_tests();
#elif defined(TPM_TEST_ENABLE_LOAD)
    DBG_PRINT("[TEST] TPM2_Load: SKIPPED (Create not enabled)\n");
#endif

#if defined(TPM_TEST_ENABLE_READPUBLIC) && defined(TPM_TEST_ENABLE_LOAD)
    TPM2_ReadPublic_test();
#elif defined(TPM_TEST_ENABLE_READPUBLIC)
    DBG_PRINT("[TEST] TPM2_ReadPublic: SKIPPED (Load not enabled)\n");
#endif

#if defined(TPM_TEST_ENABLE_OBJECTCHANGEAUTH) && defined(TPM_TEST_ENABLE_LOAD)
    TPM2_ObjectChangeAuth_test();
#elif defined(TPM_TEST_ENABLE_OBJECTCHANGEAUTH)
    DBG_PRINT("[TEST] TPM2_ObjectChangeAuth: SKIPPED (Load not enabled)\n");
#endif

    DBG_PRINT("==================================================\n");
    DBG_PRINT("[SUITE] Key Management Tests Complete\n");
    DBG_PRINT("==================================================\n\n");
}

void tpm_test(void) {
    tpm_wait_access();
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE,
                            (uint8_t *)"[INFO] TPM access granted\n", 26,
                            portMAX_DELAY);

#ifdef TPM_TEST_ENABLE_NV_DEFINE
    TPM2_NV_DefineSpace_test();
#else
    DBG_PRINT("[TEST] TPM2_NV_DefineSpace: SKIPPED (not enabled)\n");
#endif

#ifdef TPM_TEST_ENABLE_NV_WRITE_READ
    TPM2_NV_WriteRead_test();
#else
    DBG_PRINT("[TEST] TPM2_NV_WriteRead: SKIPPED (not enabled)\n");
#endif

#ifdef TPM_TEST_ENABLE_HASH
    TPM2_Hash_smoke_test();
#else
    DBG_PRINT("[TEST] TPM2_Hash: SKIPPED (not enabled)\n");
#endif

#ifdef TPM_TEST_ENABLE_SIGN
    TPM2_Sign_smoke_test();
#else
    DBG_PRINT("[TEST] TPM2_Sign: SKIPPED (not enabled)\n");
#endif

#ifdef TPM_TEST_ENABLE_VERIFY_SIGNATURE
    TPM2_VerifySignature_smoke_test();
#else
    DBG_PRINT("[TEST] TPM2_VerifySignature: SKIPPED (not enabled)\n");
#endif

#ifdef TPM_TEST_ENABLE_ENCRYPT_DECRYPT2
    TPM2_EncryptDecrypt2_smoke_test();
#else
    DBG_PRINT("[TEST] TPM2_EncryptDecrypt2: SKIPPED (not enabled)\n");
#endif

#ifdef TPM_TEST_ENABLE_RSA_ENCRYPT_DECRYPT
    TPM2_RSA_EncryptDecrypt_smoke_test();
#else
    DBG_PRINT("[TEST] TPM2_RSA_EncryptDecrypt: SKIPPED (not enabled)\n");
#endif

    /* Key Management Tests */
    TPM2_KeyManagement_test_suite();
}

int main(void) {
    IntCtrl_Ip_Init(&IntCtrlConfig_0);
    IntCtrl_Ip_EnableIrq(LPUART3_IRQn);

    Lpuart_Uart_Ip_Init(LPUART_INSTANCE, &Lpuart_Uart_Ip_xHwConfigPB_3);
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE,
                            (uint8_t *)"[INFO] Starting TPM Test\n", 25,
                            portMAX_DELAY);

    tpm_test();

    assert_report();

    while (1)
        ;

    return 0;
}

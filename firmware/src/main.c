#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include "S32K358.h"
#include "Lpuart_Uart_Ip.h"
#include "IntCtrl_Ip.h"
#include "FreeRTOS.h"
#include <stdio.h>
#include "tpm2_spec_protocol.h"

#define LPUART_INSTANCE         (3U)    // Usare LPUART3

// Debug logging - set to 1 to enable verbose output
#define TPM_DEBUG 1

#if TPM_DEBUG
#define DBG_PRINT(msg) do { \
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)(msg), strlen(msg), portMAX_DELAY); \
} while(0)

#define DBG_PRINTF(fmt, ...) do { \
    char _dbg_buf[128]; \
    int _dbg_len = snprintf(_dbg_buf, sizeof(_dbg_buf), fmt, ##__VA_ARGS__); \
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)_dbg_buf, _dbg_len, portMAX_DELAY); \
} while(0)
#else
#define DBG_PRINT(msg) ((void)0)
#define DBG_PRINTF(fmt, ...) ((void)0)
#endif

// MMIO Register Definitions
#define TPM_BASE         0x40000000

#define TPM_ACCESS       (*(volatile uint8_t*)(TPM_BASE + 0x0000)) // Used to request and check access to the TPM
#define TPM_STS          (*(volatile uint32_t*)(TPM_BASE + 0x0018))  // only 3 bytes used
#define TPM_DATA_FIFO    (*(volatile uint8_t*)(TPM_BASE + 0x0024)) // The FIFO register for sending commands and reading responses.

// Bitmask Constants
#define TPM_ACCESS_REQUEST_USE   0x02
#define TPM_ACCESS_ACTIVE_LOCAL  0x20

#define TPM_STS_COMMAND_READY    0x40
#define TPM_STS_GO               0x20
#define TPM_STS_DATA_AVAIL       0x10
#define TPM_STS_EXPECT           0x08

// TPM Utilities

const char* string_from_TPM_RC(TPM_RC rc) {
    switch (rc) {
        /*
         * Important: several TPM_RC_* macros in our header are *modifiers* or
         * *aliases* (e.g. TPM_RC_H, TPM_RC_P, TPM_RC_1, RC_VER1, TPM_RCS_*).
         * They intentionally share integer values and are not distinguishable
         * at runtime, so they must NOT appear as distinct switch labels.
         */
        case TPM_RC_SUCCESS:            return "TPM_RC_SUCCESS";
        case TPM_RC_BAD_TAG:            return "TPM_RC_BAD_TAG";

        /* Ver1 family (RC_VER1 is a base, not a standalone code) */
        case TPM_RC_FAILURE:            return "TPM_RC_FAILURE";
        case TPM_RC_COMMAND_SIZE:       return "TPM_RC_COMMAND_SIZE";
        case TPM_RC_COMMAND_CODE:       return "TPM_RC_COMMAND_CODE";
        case TPM_RC_NV_RANGE:           return "TPM_RC_NV_RANGE";
        case TPM_RC_NV_LOCKED:          return "TPM_RC_NV_LOCKED";
        case TPM_RC_NV_AUTHORIZATION:   return "TPM_RC_NV_AUTHORIZATION";
        case TPM_RC_NV_UNINITIALIZED:   return "TPM_RC_NV_UNINITIALIZED";
        case TPM_RC_NV_SPACE:           return "TPM_RC_NV_SPACE";
        case TPM_RC_NV_DEFINED:         return "TPM_RC_NV_DEFINED";

        /* Format-1 style base codes */
        case TPM_RC_ATTRIBUTES:         return "TPM_RC_ATTRIBUTES";
        case TPM_RC_HASH:               return "TPM_RC_HASH";
        case TPM_RC_VALUE:              return "TPM_RC_VALUE";
        case TPM_RC_HIERARCHY:          return "TPM_RC_HIERARCHY";
        case TPM_RC_MODE:               return "TPM_RC_MODE";
        case TPM_RC_HANDLE:             return "TPM_RC_HANDLE";
        case TPM_RCS_SIZE:              return "TPM_RCS_SIZE";
        case TPM_RC_SIGNATURE:          return "TPM_RC_SIGNATURE";
        case TPM_RC_KEY:                return "TPM_RC_KEY";

        default:                        return "UNKNOWN_RC";
    }
}

int assert_count = 0;
int assert_failures = 0;

void assert(bool expression,
    const char *msg, const char* expected, const char* actual) {
    if (!expression) {

        if (msg != NULL) {
            Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE,
                                    (uint8_t *)msg, strlen(msg),
                                    portMAX_DELAY);
        }

        // Expected: <exp>, got: <got>
        if (expected != NULL) {
            Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE,
                                    (uint8_t *)"Expected: ", 10,
                                    portMAX_DELAY);

            Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE,
                                    (uint8_t *)expected, strlen(expected),
                                    portMAX_DELAY);
        }

        if (actual != NULL) {
            Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE,
                                    (uint8_t *)", got: ", 7,
                                    portMAX_DELAY);

            Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE,
                                    (uint8_t *)actual, strlen(actual),
                                    portMAX_DELAY);
        }

        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE,
                                (uint8_t *)"\n", 1,
                                portMAX_DELAY);

        assert_failures++;
    }
    assert_count++;
}

void assert_report(void) {
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE,
                            (uint8_t *)"Assert Report\n", 14,
                            portMAX_DELAY);

    char buffer[50];
    int len = snprintf(buffer, sizeof(buffer), "Total asserts: %d\n", assert_count);
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)buffer, len, portMAX_DELAY);

    len = snprintf(buffer, sizeof(buffer), "Failed asserts: %d\n", assert_failures);
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)buffer, len, portMAX_DELAY);

    if (assert_failures == 0) {
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"All tests passed!\n", 18, portMAX_DELAY);
    } else {
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"Some tests failed!\n", 19, portMAX_DELAY);
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
        while (!tpm_send_rdy());
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
        while (!tpm_receive_rdy());
        ((uint8_t *)data)[i] = TPM_DATA_FIFO;
    }
}

/**
 * @brief Request TPM locality and busy wait until it's granted
 */
static inline
void tpm_wait_access(void) {
    TPM_ACCESS = TPM_ACCESS_REQUEST_USE;
    while (!(TPM_ACCESS & TPM_ACCESS_ACTIVE_LOCAL));
}

/**
 * @brief Notify TPM that a command is about to be sent in
 */
static inline
void tpm_command_ready(void) {
    TPM_STS |= TPM_STS_COMMAND_READY;
}

/**
 * @brief Start the execution of a command
 */
static inline
void tpm_go(void) {
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

#define TPM2_InOut(F) TPM_RC TPM2_##F(F##_In *in, F##_Out *out) { \
    tpm_rsp_header_t rsp; \
 \
    tpm_cmd_header_t cmd = { \
        .tag = TPM_ST_NO_SESSIONS, \
        .commandSize = sizeof(cmd) + sizeof(*in), \
        .commandCode = TPM_CC_##F \
    }; \
 \
    DBG_PRINTF("[DBG] TPM2_" #F ": Sending cmd (tag=0x%04X, size=%lu, code=0x%08lX)\n", \
               cmd.tag, (unsigned long)cmd.commandSize, (unsigned long)cmd.commandCode); \
 \
    tpm_command_ready(); \
    tpm_send(&cmd, sizeof(cmd)); \
    tpm_send(in, sizeof(*in)); \
 \
    tpm_go(); \
 \
    tpm_receive(&rsp, sizeof(rsp)); \
    DBG_PRINTF("[DBG] TPM2_" #F ": Received rsp (tag=0x%04X, size=%lu, rc=0x%08lX)\n", \
               rsp.tag, (unsigned long)rsp.responseSize, (unsigned long)rsp.responseCode); \
 \
    size_t remaining = 0; \
    if (rsp.responseSize >= sizeof(rsp) && rsp.responseSize <= 4096) { \
        remaining = (size_t)rsp.responseSize - sizeof(rsp); \
    } \
    DBG_PRINTF("[DBG] TPM2_" #F ": remaining=%lu bytes\n", (unsigned long)remaining); \
 \
    if (out != NULL) { \
        memset(out, 0, sizeof(*out)); \
    } \
 \
    if (rsp.responseCode != TPM_RC_SUCCESS) { \
        DBG_PRINTF("[DBG] TPM2_" #F ": Error response, draining %lu bytes\n", (unsigned long)remaining); \
        tpm_drain_bytes(remaining); \
        return rsp.responseCode; \
    } \
 \
    if (out != NULL) { \
        size_t to_read = min_size(remaining, sizeof(*out)); \
        DBG_PRINTF("[DBG] TPM2_" #F ": Reading %lu bytes to out (out size=%lu)\n", (unsigned long)to_read, (unsigned long)sizeof(*out)); \
        tpm_receive(out, to_read); \
        tpm_drain_bytes(remaining - to_read); \
    } else { \
        tpm_drain_bytes(remaining); \
    } \
 \
    return rsp.responseCode; \
}

#define TPM2_In(F) TPM_RC TPM2_##F(F##_In *in) { \
    tpm_rsp_header_t rsp; \
 \
    tpm_cmd_header_t cmd = { \
        .tag = TPM_ST_NO_SESSIONS, \
        .commandSize = sizeof(cmd) + sizeof(*in), \
        .commandCode = TPM_CC_##F \
    }; \
 \
    DBG_PRINTF("[DBG] TPM2_" #F ": Sending cmd (tag=0x%04X, size=%lu, code=0x%08lX)\n", \
               cmd.tag, (unsigned long)cmd.commandSize, (unsigned long)cmd.commandCode); \
 \
    tpm_command_ready(); \
    tpm_send(&cmd, sizeof(cmd)); \
    tpm_send(in, sizeof(*in)); \
 \
    tpm_go(); \
 \
    tpm_receive(&rsp, sizeof(rsp)); \
    DBG_PRINTF("[DBG] TPM2_" #F ": Received rsp (tag=0x%04X, size=%lu, rc=0x%08lX)\n", \
               rsp.tag, (unsigned long)rsp.responseSize, (unsigned long)rsp.responseCode); \
 \
     size_t remaining = 0; \
     if (rsp.responseSize >= sizeof(rsp) && rsp.responseSize <= 4096) { \
          remaining = (size_t)rsp.responseSize - sizeof(rsp); \
     } \
     tpm_drain_bytes(remaining); \
 \
     return rsp.responseCode; \
}

TPM2_In(NV_DefineSpace)
TPM2_In(NV_Write)
TPM2_InOut(NV_Read)

TPM2_InOut(Sign)
TPM2_InOut(VerifySignature)
TPM2_InOut(Hash)
TPM2_InOut(EncryptDecrypt2)
TPM2_InOut(RSA_Encrypt)
TPM2_InOut(RSA_Decrypt)

// TPM Tests

void TPM2_NV_DefineSpace_test(void) {
    TPM_RC res;

    NV_DefineSpace_In test_input = {
        .authHandle = TPM_RH_OWNER,
        .auth = {
            .size = 0, // No authorization value (password) required for this example
            .buffer = {0}
        },
        .publicInfo = {
            .size = 0,
            .nvPublic = {
                .nvIndex = 0x01500016, // A valid index in the allowed range
                .nameAlg = TPM_ALG_NULL,
                .attributes = {.OWNERREAD = 1, .OWNERWRITE = 1},
                .dataSize = 32, // The size of the NV space in bytes
                .authPolicy = {
                    .size = 0, // No policy required for this example
                    .buffer = {0}
                },
            },
        }
    };

    res = TPM2_NV_DefineSpace(&test_input);
    assert(res == TPM_RC_SUCCESS,
           "TPM2_NV_DefineSpace failed",
           string_from_TPM_RC(TPM_RC_SUCCESS),
           string_from_TPM_RC(res));
}

void TPM2_NV_WriteRead_test(void) {
    TPM_RC res;

    // Use previously defined nv_index
    const TPMI_RH_NV_INDEX nv_index = 0x01500016;
    const UINT16 data_size = 32;

    // --- 1. Write Data to NV Memory ---
    TPM2B_MAX_NV_BUFFER write_data = {
        .size = data_size,
        .buffer = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F }
    };

    NV_Write_In write_input = {
        .authHandle = TPM_RH_OWNER,       // Authorize as Owner
        .nvIndex = nv_index,            // The index to write to
        .data = write_data,               // The data to write
        .offset = 0                       // Write at the beginning
    };

    res = TPM2_NV_Write(&write_input);
    assert(res == TPM_RC_SUCCESS,
           "TPM2_NV_Write failed",
           string_from_TPM_RC(TPM_RC_SUCCESS),
           string_from_TPM_RC(res));

    // --- 2. Read Data from NV Memory ---
    NV_Read_In read_input = {
        .authHandle = TPM_RH_OWNER,       // Authorize as Owner
        .nvIndex = nv_index,            // The index to read from
        .size = data_size,                // Number of bytes to read
        .offset = 0                       // Read from the beginning
    };

    NV_Read_Out read_output = {0};

    res = TPM2_NV_Read(&read_input, &read_output);
    assert(res == TPM_RC_SUCCESS,
           "TPM2_NV_Read failed",
           string_from_TPM_RC(TPM_RC_SUCCESS),
           string_from_TPM_RC(res));

    // --- 3. Compare Actual Data with Expected ---
    char expected_size_str[12];
    char actual_size_str[12];
    snprintf(expected_size_str, sizeof(expected_size_str), "%u", write_data.size);
    snprintf(actual_size_str, sizeof(actual_size_str), "%u", read_output.data.size);
    assert(read_output.data.size == write_data.size,
           "NV Read size mismatch",
           expected_size_str,
           actual_size_str);

    assert(memcmp(read_output.data.buffer, write_data.buffer, write_data.size) == 0,
           "NV Read data mismatch", NULL, NULL);
}

void TPM2_Hash_smoke_test(void) {
    Hash_In in = {0};
    Hash_Out out = {0};
    in.data.dataSize = 4;
    in.data.data[0] = 'A';
    in.data.data[1] = 'B';
    in.data.data[2] = 'C';
    in.data.data[3] = 'D';

    TPM_RC res = TPM2_Hash(&in, &out);
    assert(res != TPM_RC_BAD_TAG,
           "TPM2_Hash bad tag",
           "!= TPM_RC_BAD_TAG",
           string_from_TPM_RC(res));
    assert(res != TPM_RC_COMMAND_SIZE,
           "TPM2_Hash command size",
           "!= TPM_RC_COMMAND_SIZE",
           string_from_TPM_RC(res));

    if (res == TPM_RC_SUCCESS) {
        assert(out.digest.size > 0,
               "TPM2_Hash digest size",
               "> 0",
               "0");
    }
}

void TPM2_Sign_smoke_test(void) {
    Sign_In in = {0};
    Sign_Out out = {0};

    in.keyHandle.keySize = 8;
    for (int i = 0; i < 8; i++) {
        in.keyHandle.key[i] = (uint8_t)(i + 1);
    }

    in.data.dataSize = 4;
    in.data.data[0] = 'A';
    in.data.data[1] = 'B';
    in.data.data[2] = 'C';
    in.data.data[3] = 'D';

    TPM_RC res = TPM2_Sign(&in, &out);
    assert(res != TPM_RC_BAD_TAG,
           "TPM2_Sign bad tag",
           "!= TPM_RC_BAD_TAG",
           string_from_TPM_RC(res));
    assert(res != TPM_RC_COMMAND_SIZE,
           "TPM2_Sign command size",
           "!= TPM_RC_COMMAND_SIZE",
           string_from_TPM_RC(res));

    if (res == TPM_RC_SUCCESS) {
        assert(out.signature.signatureSize > 0,
               "TPM2_Sign signature size",
               "> 0",
               "0");
    }
}

void TPM2_VerifySignature_smoke_test(void) {
    VerifySignature_In in = {0};
    VerifySignature_Out out = {0};

    in.keyHandle.keySize = 8;
    for (int i = 0; i < 8; i++) {
        in.keyHandle.key[i] = (uint8_t)(i + 1);
    }

    in.data.dataSize = 4;
    in.data.data[0] = 'A';
    in.data.data[1] = 'B';
    in.data.data[2] = 'C';
    in.data.data[3] = 'D';

    in.signature.signatureSize = TPM_MAX_SIGNATURE_SIZE;
    for (int i = 0; i < TPM_MAX_SIGNATURE_SIZE; i++) {
        in.signature.signature[i] = (uint8_t)(0xA5u ^ (uint8_t)i);
    }

    TPM_RC res = TPM2_VerifySignature(&in, &out);
    assert(res != TPM_RC_BAD_TAG,
           "TPM2_VerifySignature bad tag",
           "!= TPM_RC_BAD_TAG",
           string_from_TPM_RC(res));
    assert(res != TPM_RC_COMMAND_SIZE,
           "TPM2_VerifySignature command size",
           "!= TPM_RC_COMMAND_SIZE",
           string_from_TPM_RC(res));

    (void)out;
}

void TPM2_EncryptDecrypt2_smoke_test(void) {
    EncryptDecrypt2_In in = {0};
    EncryptDecrypt2_Out out = {0};

    in.keyHandle.keySize = 8;
    for (int i = 0; i < 8; i++) {
        in.keyHandle.key[i] = (uint8_t)(i + 1);
    }

    in.decrypt = 0;
    in.symDef.algorithm = TPM_ALG_AES;
    in.symDef.mode = TPM_ALG_CBC;
    in.symDef.keyBits = 128;

    in.ivIn.ivSize = 16;
    for (int i = 0; i < 16; i++) {
        in.ivIn.iv[i] = (uint8_t)i;
    }

    in.inData.bufferSize = 16;
    for (int i = 0; i < 16; i++) {
        in.inData.buffer[i] = (uint8_t)('A' + i);
    }

    TPM_RC res = TPM2_EncryptDecrypt2(&in, &out);
    assert(res != TPM_RC_BAD_TAG,
           "TPM2_EncryptDecrypt2 bad tag",
           "!= TPM_RC_BAD_TAG",
           string_from_TPM_RC(res));
    assert(res != TPM_RC_COMMAND_SIZE,
           "TPM2_EncryptDecrypt2 command size",
           "!= TPM_RC_COMMAND_SIZE",
           string_from_TPM_RC(res));

    if (res == TPM_RC_SUCCESS) {
        char expected_size_str[12];
        char actual_size_str[12];
        snprintf(expected_size_str, sizeof(expected_size_str), "%u", in.inData.bufferSize);
        snprintf(actual_size_str, sizeof(actual_size_str), "%u", out.outData.bufferSize);
        assert(out.outData.bufferSize == in.inData.bufferSize,
               "EncryptDecrypt2 size mismatch",
               expected_size_str,
               actual_size_str);
    }
}

void TPM2_RSA_EncryptDecrypt_smoke_test(void) {
    RSA_Encrypt_In enc_in = {0};
    RSA_Encrypt_Out enc_out = {0};

    enc_in.keyHandle.keySize = 8;
    for (int i = 0; i < 8; i++) {
        enc_in.keyHandle.key[i] = (uint8_t)(i + 1);
    }
    enc_in.data.dataSize = 4;
    enc_in.data.data[0] = 'A';
    enc_in.data.data[1] = 'B';
    enc_in.data.data[2] = 'C';
    enc_in.data.data[3] = 'D';

    TPM_RC res = TPM2_RSA_Encrypt(&enc_in, &enc_out);
    assert(res != TPM_RC_BAD_TAG,
           "TPM2_RSA_Encrypt bad tag",
           "!= TPM_RC_BAD_TAG",
           string_from_TPM_RC(res));
    assert(res != TPM_RC_COMMAND_SIZE,
           "TPM2_RSA_Encrypt command size",
           "!= TPM_RC_COMMAND_SIZE",
           string_from_TPM_RC(res));

    RSA_Decrypt_In dec_in = {0};
    RSA_Decrypt_Out dec_out = {0};

    dec_in.keyHandle.keySize = 8;
    for (int i = 0; i < 8; i++) {
        dec_in.keyHandle.key[i] = (uint8_t)(i + 1);
    }
    dec_in.encrypted.dataSize = 4;
    dec_in.encrypted.data[0] = 0x11;
    dec_in.encrypted.data[1] = 0x22;
    dec_in.encrypted.data[2] = 0x33;
    dec_in.encrypted.data[3] = 0x44;

    res = TPM2_RSA_Decrypt(&dec_in, &dec_out);
    assert(res != TPM_RC_BAD_TAG,
           "TPM2_RSA_Decrypt bad tag",
           "!= TPM_RC_BAD_TAG",
           string_from_TPM_RC(res));
    assert(res != TPM_RC_COMMAND_SIZE,
           "TPM2_RSA_Decrypt command size",
           "!= TPM_RC_COMMAND_SIZE",
           string_from_TPM_RC(res));

    (void)enc_out;
    (void)dec_out;
}

void tpm_test(void) {
    tpm_wait_access();
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[INFO] TPM access granted\n", 26, portMAX_DELAY);

    TPM2_NV_DefineSpace_test();
    TPM2_NV_WriteRead_test();

    TPM2_Hash_smoke_test();
    TPM2_Sign_smoke_test();
    TPM2_VerifySignature_smoke_test();
    TPM2_EncryptDecrypt2_smoke_test();
    TPM2_RSA_EncryptDecrypt_smoke_test();
}

int main(void) {

    IntCtrl_Ip_Init(&IntCtrlConfig_0);
    IntCtrl_Ip_EnableIrq(LPUART3_IRQn);

    Lpuart_Uart_Ip_Init(LPUART_INSTANCE, &Lpuart_Uart_Ip_xHwConfigPB_3);
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[INFO] Starting TPM Test\n", 25, portMAX_DELAY);

    tpm_test();

    assert_report();

    while (1);

    return 0;
}

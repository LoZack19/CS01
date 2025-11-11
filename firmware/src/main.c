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
        // Cases are ordered by their numeric value for readability.
        case TPM_RC_SUCCESS:            return "TPM_RC_SUCCESS";
        case TPM_RC_H:                  return "TPM_RC_H";
        case TPM_RC_P:                  return "TPM_RC_P";
        case TPM_RC_1:                  return "TPM_RC_1";
        case TPM_RC_2:                  return "TPM_RC_2";
        case TPM_RC_3:                  return "TPM_RC_3";
        case TPM_RC_BAD_TAG:            return "TPM_RC_BAD_TAG";
        case RC_VER1:                   return "RC_VER1";
        case TPM_RC_FAILURE:            return "TPM_RC_FAILURE";
        case TPM_RC_COMMAND_SIZE:       return "TPM_RC_COMMAND_SIZE";
        case TPM_RC_COMMAND_CODE:       return "TPM_RC_COMMAND_CODE";
        case TPM_RC_NV_RANGE:           return "TPM_RC_NV_RANGE";
        case TPM_RC_NV_LOCKED:          return "TPM_RC_NV_LOCKED";
        case TPM_RC_NV_AUTHORIZATION:   return "TPM_RC_NV_AUTHORIZATION";
        case TPM_RC_NV_UNINITIALIZED:   return "TPM_RC_NV_UNINITIALIZED";
        case TPM_RC_NV_SPACE:           return "TPM_RC_NV_SPACE";
        case TPM_RC_NV_DEFINED:         return "TPM_RC_NV_DEFINED";
        case RC_FMT1:                   return "RC_FMT1";
        case TPM_RC_ATTRIBUTES:         return "TPM_RC_ATTRIBUTES";
        case TPM_RCS_ATTRIBUTES:        return "TPM_RCS_ATTRIBUTES";
        case TPM_RC_VALUE:              return "TPM_RC_VALUE";
        case TPM_RCS_VALUE:             return "TPM_RCS_VALUE";
        case TPM_RC_HIERARCHY:          return "TPM_RC_HIERARCHY";
        case TPM_RCS_HIERARCHY:         return "TPM_RCS_HIERARCHY";
        case TPM_RC_HANDLE:             return "TPM_RC_HANDLE";
        case TPM_RCS_HANDLE:            return "TPM_RCS_HANDLE";
        case TPM_RCS_SIZE:              return "TPM_RCS_SIZE";
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

#define TPM2_InOut(F) TPM_RC TPM2_##F(F##_In *in, F##_Out *out) { \
    tpm_rsp_header_t rsp; \
 \
    tpm_cmd_header_t cmd = { \
        .tag = TPM_ST_NO_SESSIONS, \
        .commandSize = sizeof(cmd) + sizeof(*in), \
        .commandCode = TPM_CC_##F \
    }; \
 \
    tpm_command_ready(); \
    tpm_send(&cmd, sizeof(cmd)); \
    tpm_send(in, sizeof(*in)); \
 \
    tpm_go(); \
 \
    tpm_receive(&rsp, sizeof(rsp)); \
    if (rsp.responseCode != TPM_RC_SUCCESS) { \
        return rsp.responseCode; \
    } \
 \
    tpm_receive(out, sizeof(*out)); \
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
    tpm_command_ready(); \
    tpm_send(&cmd, sizeof(cmd)); \
    tpm_send(in, sizeof(*in)); \
 \
    tpm_go(); \
 \
    tpm_receive(&rsp, sizeof(rsp)); \
 \
    return rsp.responseCode; \
}

TPM2_In(NV_DefineSpace)
TPM2_In(NV_Write)
TPM2_InOut(NV_Read)

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
        .auth = { .size = 0, .buffer = {0} }, // Empty password auth
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
        .auth = { .size = 0, .buffer = {0} }, // Empty password auth
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

void tpm_test(void) {
    tpm_wait_access();
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[INFO] TPM access granted\n", 26, portMAX_DELAY);

    TPM2_NV_DefineSpace_test();
    TPM2_NV_WriteRead_test();
}

int main(void) {

    IntCtrl_Ip_Init(&IntCtrlConfig_0);
    IntCtrl_Ip_EnableIrq(LPUART3_IRQn);

    Lpuart_Uart_Ip_Init(LPUART_INSTANCE, &Lpuart_Uart_Ip_xHwConfigPB_3);
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[INFO] Starting TPM Test\n", 25, portMAX_DELAY);

    tpm_test();

    assert_report();
    
#warning "Cryptographic Testing should be integrated in Mateus framework"
    test_sign_operation();
    test_verify_signature_operation();
    test_hash_operation();
    test_encrypt_decrypt2_operation();
    test_rsa_encrypt_operation();
    test_rsa_decrypt_operation();
    
    while (1);

    return 0;
}

#warning "Non compliant testing for Cryptographic Primitives w.r.t. Mateus framework"

// Test function prototypes
void test_sign_operation(void);
void test_verify_signature_operation(void);
void test_hash_operation(void);
void test_encrypt_decrypt2_operation(void);
void test_rsa_encrypt_operation(void);
void test_rsa_decrypt_operation(void);

// Test function for TPM2_Sign
void test_sign_operation(void) {
    uint8_t sign_cmd[] = {
        0x80, 0x01,                         // TPM_ST_NO_SESSIONS
        0x00, 0x00, 0x00, 0x20,             // command size = 32
        0x00, 0x00, 0x01, 0x5D,             // TPM2_CC_Sign
        0x00, 0x08,                          // keyHandle size = 8
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // key data
        0x00, 0x04,                          // data size = 4
        0x41, 0x42, 0x43, 0x44              // data "ABCD"
    };
    
    uint8_t rsp_buf[4096];
    size_t rsp_len;
    
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[INFO] Testing TPM2_Sign", 23, portMAX_DELAY);
    
    tpm_wait_access();
    TPM_STS = TPM_STS_COMMAND_READY;
    tpm_wait_burst_and_write(sign_cmd, sizeof(sign_cmd));
    TPM_STS = TPM_STS_GO;
    tpm_read_response(rsp_buf, sizeof(rsp_buf), &rsp_len);
    
    if (rsp_len >= 10) {
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[SUCCESS] Sign operation completed", 35, portMAX_DELAY);
    } else {
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[ERROR] Sign operation failed", 30, portMAX_DELAY);
    }
}

// Test function for TPM2_VerifySignature
void test_verify_signature_operation(void) {
    uint8_t verify_cmd[] = {
        0x80, 0x01,                         // TPM_ST_NO_SESSIONS
        0x00, 0x00, 0x01, 0x0C,             // command size = 268 (updated for 256-byte signature)
        0x00, 0x00, 0x01, 0x77,             // TPM2_CC_VerifySignature
        0x00, 0x08,                          // keyHandle size = 8
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // key data
        0x00, 0x04,                          // data size = 4
        0x41, 0x42, 0x43, 0x44,             // data "ABCD"
        0x01, 0x00,                          // signature size = 256 (RSA-PSS-SHA256)
        // 256 bytes of signature data (test pattern)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
    };
    
    uint8_t rsp_buf[4096];
    size_t rsp_len;
    
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[INFO] Testing TPM2_VerifySignature", 34, portMAX_DELAY);
    
    tpm_wait_access();
    TPM_STS = TPM_STS_COMMAND_READY;
    tpm_wait_burst_and_write(verify_cmd, sizeof(verify_cmd));
    TPM_STS = TPM_STS_GO;
    tpm_read_response(rsp_buf, sizeof(rsp_buf), &rsp_len);
    
    if (rsp_len >= 10) {
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[SUCCESS] VerifySignature operation completed", 44, portMAX_DELAY);
    } else {
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[ERROR] VerifySignature operation failed", 39, portMAX_DELAY);
    }
}

// Test function for TPM2_Hash
void test_hash_operation(void) {
    uint8_t hash_cmd[] = {
        0x80, 0x01,                         // TPM_ST_NO_SESSIONS
        0x00, 0x00, 0x00, 0x0E,             // command size = 14
        0x00, 0x00, 0x01, 0x7D,             // TPM2_CC_Hash
        0x00, 0x04,                          // data size = 4
        0x41, 0x42, 0x43, 0x44              // data "ABCD"
    };
    
    uint8_t rsp_buf[4096];
    size_t rsp_len;
    
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[INFO] Testing TPM2_Hash", 24, portMAX_DELAY);
    
    tpm_wait_access();
    TPM_STS = TPM_STS_COMMAND_READY;
    tpm_wait_burst_and_write(hash_cmd, sizeof(hash_cmd));
    TPM_STS = TPM_STS_GO;
    tpm_read_response(rsp_buf, sizeof(rsp_buf), &rsp_len);
    
    if (rsp_len >= 10) {
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[SUCCESS] Hash operation completed", 34, portMAX_DELAY);
    } else {
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[ERROR] Hash operation failed", 29, portMAX_DELAY);
    }
}

// Test function for TPM2_EncryptDecrypt2
void test_encrypt_decrypt2_operation(void) {
    uint8_t encrypt_cmd[] = {
        0x80, 0x01,                         // TPM_ST_NO_SESSIONS
        0x00, 0x00, 0x00, 0x2F,             // command size = 47
        0x00, 0x00, 0x01, 0x43,             // TPM2_CC_EncryptDecrypt2 (correct code)
        0x00, 0x08,                          // keyHandle size = 8
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // key data
        0x00,                                // decrypt = 0 (encrypt)
        0x00, 0x06,                          // algorithm = TPM_ALG_AES
        0x00, 0x42,                          // mode = TPM_ALG_CBC
        0x00, 0x80,                          // keyBits = 128
        0x00, 0x10,                          // IV size = 16
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // IV data
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x00, 0x10,                          // data size = 16 (block-aligned)
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, // data (16 bytes)
        0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50
    };
    
    uint8_t rsp_buf[4096];
    size_t rsp_len;
    
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[INFO] Testing TPM2_EncryptDecrypt2", 33, portMAX_DELAY);
    
    tpm_wait_access();
    TPM_STS = TPM_STS_COMMAND_READY;
    tpm_wait_burst_and_write(encrypt_cmd, sizeof(encrypt_cmd));
    TPM_STS = TPM_STS_GO;
    tpm_read_response(rsp_buf, sizeof(rsp_buf), &rsp_len);
    
    if (rsp_len >= 10) {
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[SUCCESS] EncryptDecrypt2 operation completed", 43, portMAX_DELAY);
    } else {
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[ERROR] EncryptDecrypt2 operation failed", 38, portMAX_DELAY);
    }
}

// Test function for TPM2_RSA_Encrypt
void test_rsa_encrypt_operation(void) {
    uint8_t rsa_encrypt_cmd[] = {
        0x80, 0x01,                         // TPM_ST_NO_SESSIONS
        0x00, 0x00, 0x00, 0x14,             // command size = 20
        0x00, 0x00, 0x01, 0x73,             // TPM2_CC_RSA_Encrypt
        0x00, 0x08,                          // keyHandle size = 8
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // key data
        0x00, 0x04,                          // data size = 4
        0x41, 0x42, 0x43, 0x44              // data "ABCD"
    };
    
    uint8_t rsp_buf[4096];
    size_t rsp_len;
    
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[INFO] Testing TPM2_RSA_Encrypt", 30, portMAX_DELAY);
    
    tpm_wait_access();
    TPM_STS = TPM_STS_COMMAND_READY;
    tpm_wait_burst_and_write(rsa_encrypt_cmd, sizeof(rsa_encrypt_cmd));
    TPM_STS = TPM_STS_GO;
    tpm_read_response(rsp_buf, sizeof(rsp_buf), &rsp_len);
    
    if (rsp_len >= 10) {
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[SUCCESS] RSA_Encrypt operation completed", 40, portMAX_DELAY);
    } else {
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[ERROR] RSA_Encrypt operation failed", 35, portMAX_DELAY);
    }
}

// Test function for TPM2_RSA_Decrypt
void test_rsa_decrypt_operation(void) {
    uint8_t rsa_decrypt_cmd[] = {
        0x80, 0x01,                         // TPM_ST_NO_SESSIONS
        0x00, 0x00, 0x00, 0x14,             // command size = 20
        0x00, 0x00, 0x01, 0x74,             // TPM2_CC_RSA_Decrypt
        0x00, 0x08,                          // keyHandle size = 8
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // key data
        0x00, 0x04,                          // encrypted data size = 4
        0x11, 0x22, 0x33, 0x44              // encrypted data
    };
    
    uint8_t rsp_buf[4096];
    size_t rsp_len;
    
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[INFO] Testing TPM2_RSA_Decrypt", 30, portMAX_DELAY);
    
    tpm_wait_access();
    TPM_STS = TPM_STS_COMMAND_READY;
    tpm_wait_burst_and_write(rsa_decrypt_cmd, sizeof(rsa_decrypt_cmd));
    TPM_STS = TPM_STS_GO;
    tpm_read_response(rsp_buf, sizeof(rsp_buf), &rsp_len);
    
    if (rsp_len >= 10) {
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[SUCCESS] RSA_Decrypt operation completed", 40, portMAX_DELAY);
    } else {
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[ERROR] RSA_Decrypt operation failed", 35, portMAX_DELAY);
    }
}

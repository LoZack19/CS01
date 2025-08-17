#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "S32K358.h"
#include "Lpuart_Uart_Ip.h"
#include "IntCtrl_Ip.h"
#include "FreeRTOS.h"
#include <stdio.h>

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

// Sample Command: TPM2_GetCapability
// This command queries the TPM for its properties.
uint8_t tpm_cmd[] = {
    0x80, 0x01,                         // TPM_ST_NO_SESSIONS
    0x00, 0x00, 0x00, 0x0E,             // command size = 14
    0x00, 0x00, 0x01, 0x7A,             // TPM2_CC_GetCapability
    0x00, 0x00, 0x00, 0x06              // TPM_CAP_TPM_PROPERTIES
};

// Add TPM2_GetRandom command (request 8 random bytes)
uint8_t tpm_getrandom_cmd[] = {
    0x80, 0x01,                         // TPM_ST_NO_SESSIONS
    0x00, 0x00, 0x00, 0x0C,             // command size = 12
    0x00, 0x00, 0x01, 0x7B,             // TPM2_CC_GetRandom (0x0000017B)
    0x00, 0x08                          // bytesRequested = 8 (big-endian)
};

// Expected response for TPM2_GetRandom (example 8 random bytes)
uint8_t tpm_getrandom_rsp_expected[] = {
    0x80, 0x01,             // TPM_ST_NO_SESSIONS
    0x00, 0x00, 0x00, 0x2C, // response size = 10 + 2 + 32 = 44
    0x00, 0x00, 0x00, 0x00, // TPM_RC_SUCCESS
    0x00, 0x08,             // digest size = 8 bytes
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// Requests access to TPM locality 0 and waits until it is granted.
void tpm_wait_access(void) {
    TPM_ACCESS = TPM_ACCESS_REQUEST_USE;
    while (!(TPM_ACCESS & TPM_ACCESS_ACTIVE_LOCAL));
}

// Writes the command to the TPM FIFO, handling burst size as reported by TPM_STS.
void tpm_wait_burst_and_write(const uint8_t* data, size_t len) {
    size_t offset = 0;
    while (offset < len) {
        uint32_t sts = TPM_STS;
        uint16_t burst = (sts >> 8) & 0xFFFF;
        if (burst == 0) continue; // Wait for burst to become available

        size_t count = (burst < (len - offset)) ? burst : (len - offset);
        for (size_t i = 0; i < count; ++i)
            TPM_DATA_FIFO = data[offset + i]; // Write data byte-by-byte

        offset += count;
    }
}

// Reads the TPM response from the FIFO into buf, up to max_len bytes.
// Sets actual_len to the number of bytes read.
void tpm_read_response(uint8_t* buf, size_t max_len, size_t* actual_len) {
    while (!(TPM_STS & TPM_STS_DATA_AVAIL));  // Wait for response to be available

    // Read the 10-byte TPM response header (tag, size, code)
    for (int i = 0; i < 10; ++i)
        buf[i] = TPM_DATA_FIFO;

    // Extract total response size from header
    uint32_t total = (buf[2] << 24) | (buf[3] << 16) | (buf[4] << 8) | buf[5];
    if (total > max_len) total = max_len;

    // Read the rest of the response
    for (size_t i = 10; i < total; ++i)
        buf[i] = TPM_DATA_FIFO;

    *actual_len = total;
}

// Function to print a response packet on the console for debugging purposes
void print_response(const uint8_t* rsp, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (i > 0 && i % 16 == 0) {
            Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"\n", 1, portMAX_DELAY);
        }
        char hexbuf[6];
        int hexlen = snprintf(hexbuf, sizeof(hexbuf), "0x%02X ", rsp[i]);
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)hexbuf, hexlen, portMAX_DELAY);
    }
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"\n", 1, portMAX_DELAY);
}

// Function to report expected response and actual response for debugging
void report_expected_response(const uint8_t* expected, const uint8_t* actual, size_t len) {
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[DEBUG] Expected Response: ", 28, portMAX_DELAY);
    print_response(expected, len);
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[DEBUG] Actual Response: ", 26, portMAX_DELAY);
    print_response(actual, len);
}

int main(void) {
    uint8_t rsp_buf[4096];
    size_t rsp_len;

    IntCtrl_Ip_Init(&IntCtrlConfig_0);
    IntCtrl_Ip_EnableIrq(LPUART3_IRQn);

    Lpuart_Uart_Ip_Init(LPUART_INSTANCE, &Lpuart_Uart_Ip_xHwConfigPB_3);
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[INFO] Starting TPM Test\n", 25, portMAX_DELAY);

    tpm_wait_access();
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[INFO] Access granted to TPM locality 0\n", 40, portMAX_DELAY);

    TPM_STS = TPM_STS_COMMAND_READY;
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[INFO] Sending TPM command\n", 27, portMAX_DELAY);

    tpm_wait_burst_and_write(tpm_getrandom_cmd, sizeof(tpm_getrandom_cmd));
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[INFO] Command sent, waiting for response\n", 42, portMAX_DELAY);

    TPM_STS = TPM_STS_GO;
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[INFO] Command execution started\n", 33, portMAX_DELAY);

    tpm_read_response(rsp_buf, sizeof(rsp_buf), &rsp_len);
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[INFO] Response received\n", 25, portMAX_DELAY);

    if (rsp_len < sizeof(tpm_getrandom_rsp_expected)) {
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[ERROR] GetRandom: Response is too short\n", 41, portMAX_DELAY);
        report_expected_response(tpm_getrandom_rsp_expected, rsp_buf, rsp_len);
        while (1);
    }

    if (memcmp(rsp_buf, tpm_getrandom_rsp_expected, sizeof(tpm_getrandom_rsp_expected) - 32) != 0) {
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[ERROR] GetRandom: Response does not match expected\n", 52, portMAX_DELAY);
        report_expected_response(tpm_getrandom_rsp_expected, rsp_buf, rsp_len);
        while (1);
    }

    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[SUCCESS] GetRandom success\n", 28, portMAX_DELAY);
    
    // Test cryptographic operations
    test_sign_operation();
    test_verify_signature_operation();
    test_hash_operation();
    test_encrypt_decrypt2_operation();
    test_rsa_encrypt_operation();
    test_rsa_decrypt_operation();
    
    while (1);

    return 0;
}

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

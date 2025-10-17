#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include "S32K358.h"
#include "Lpuart_Uart_Ip.h"
#include "IntCtrl_Ip.h"
#include "FreeRTOS.h"
#include <stdio.h>
#include "../../qemu/include/hw/misc/tpm2_spec_protocol.h"

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
        case TPM_RC_SUCCESS:      return "TPM_RC_SUCCESS";
        case TPM_RC_BAD_TAG:      return "TPM_RC_BAD_TAG";
        case TPM_RC_P:            return "TPM_RC_P";
        case RC_FMT1:             return "RC_FMT1";
        case TPM_RC_ATTRIBUTES:   return "TPM_RC_ATTRIBUTES";
        case TPM_RC_HIERARCHY:    return "TPM_RC_HIERARCHY";
        case TPM_RC_HANDLE:       return "TPM_RC_HANDLE";
        case TPM_RCS_SIZE:        return "TPM_RCS_SIZE";
        case TPM_RC_1:            return "TPM_RC_1";
        case TPM_RC_COMMAND_SIZE: return "TPM_RC_COMMAND_SIZE";
        case TPM_RC_COMMAND_CODE: return "TPM_RC_COMMAND_CODE";
        case TPM_RC_NV_SPACE:     return "TPM_RC_NV_SPACE";
        case TPM_RC_NV_DEFINED:   return "TPM_RC_NV_DEFINED";
        case TPM_RC_2:            return "TPM_RC_2";
        case TPM_RC_3:            return "TPM_RC_3";
        default:                  return "UNKNOWN_RC";
    }
}

int assert_count = 0;
int assert_failures = 0;

void assert(bool expression, const char* expected, const char* actual) {
    if (!expression) {
        // Expected: <exp>, got: <got>
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE,
                                (uint8_t *)"Expected: ", 10,
                                portMAX_DELAY);
        
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE,
                                (uint8_t *)expected, strlen(expected),
                                portMAX_DELAY);
        
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE,
                                (uint8_t *)", got: ", 7,
                                portMAX_DELAY);

        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE,
                                (uint8_t *)actual, strlen(actual),
                                portMAX_DELAY);

        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE,
                                (uint8_t *)"\n", 1,
                                portMAX_DELAY);
        
        assert_failures++;
    }
    assert_count++;

    for (;;);
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

TPM_RC TPM2_NV_DefineSpace(NV_DefineSpace_In *in) {
    tpm_rsp_header_t rsp;
    
    tpm_cmd_header_t cmd = {
        .tag = TPM_ST_NO_SESSIONS,
        .commandSize = sizeof(cmd) + sizeof(*in),
        .commandCode = TPM_CC_NV_DefineSpace
    };
    
    tpm_command_ready();
    tpm_send(&cmd, sizeof(cmd));
    tpm_send(in, sizeof(*in));
    
    tpm_go();
    
    tpm_receive(&rsp, sizeof(rsp));
    
    return rsp.responseCode;
}

// TPM Tests

void TPM2_NV_DefineSpace_test() {
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
           string_from_TPM_RC(TPM_RC_SUCCESS), 
           string_from_TPM_RC(res));
}

void tpm_test() {
    tpm_wait_access();
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[INFO] TPM access granted\n", 26, portMAX_DELAY);

    TPM2_NV_DefineSpace_test();
}

int main(void) {
    uint8_t rsp_buf[4096];
    size_t rsp_len;

    IntCtrl_Ip_Init(&IntCtrlConfig_0);
    IntCtrl_Ip_EnableIrq(LPUART3_IRQn);

    Lpuart_Uart_Ip_Init(LPUART_INSTANCE, &Lpuart_Uart_Ip_xHwConfigPB_3);
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"[INFO] Starting TPM Test\n", 25, portMAX_DELAY);

    tpm_test();

    return 0;
}

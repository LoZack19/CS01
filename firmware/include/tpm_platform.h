#ifndef TPM_PLATFORM_H
#define TPM_PLATFORM_H

/*
 * tpm_platform.h — Shared platform definitions for the TPM test firmware.
 *
 * Provides:
 *   - Standard library includes
 *   - NXP S32K358 / FreeRTOS platform includes
 *   - LPUART instance selection
 *   - Debug-print macros (DBG_PRINT / DBG_PRINTF)
 *   - TPM MMIO register definitions and bitmask constants
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>

#include "S32K358.h"
#include "Lpuart_Uart_Ip.h"
#include "IntCtrl_Ip.h"
#include "FreeRTOS.h"

/* ---- LPUART instance --------------------------------------------------- */
#define LPUART_INSTANCE (3U)

/* ---- Debug logging ----------------------------------------------------- */
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

/* ---- MMIO Register Definitions ----------------------------------------- */
#define TPM_BASE 0x40000000

#define TPM_ACCESS \
    (*(volatile uint8_t *)(TPM_BASE + 0x0000)) /* Request / check access */
#define TPM_STS \
    (*(volatile uint32_t *)(TPM_BASE + 0x0018)) /* Status (3 bytes used) */
#define TPM_DATA_FIFO \
    (*(volatile uint8_t *)(TPM_BASE + 0x0024)) /* Command/response FIFO */

/* ---- Bitmask Constants ------------------------------------------------- */
#define TPM_ACCESS_REQUEST_USE  0x02
#define TPM_ACCESS_ACTIVE_LOCAL 0x20

#define TPM_STS_COMMAND_READY 0x40
#define TPM_STS_GO            0x20
#define TPM_STS_DATA_AVAIL    0x10
#define TPM_STS_EXPECT        0x08

#endif /* TPM_PLATFORM_H */

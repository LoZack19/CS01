/**
 * @file tpm_platform.h
 * @brief Platform abstraction layer for the TPM test firmware on NXP S32K358.
 *
 * Centralises all hardware-specific definitions:
 *   - NXP S32K358 / FreeRTOS includes
 *   - LPUART3 instance selection for debug output
 *   - Debug-print macros (DBG_PRINT / DBG_PRINTF)
 *   - TPM MMIO register addresses and bitmask constants (§3.1)
 *
 * The MMIO layout mirrors the TCG PC Client TIS registers mapped
 * at @c TPM_BASE by the QEMU s32k358_tpm device model.
 */

#ifndef TPM_PLATFORM_H
#define TPM_PLATFORM_H

/* ---- Standard library -------------------------------------------------- */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>

/* ---- NXP S32K358 / FreeRTOS platform ----------------------------------- */
#include "S32K358.h"
#include "Lpuart_Uart_Ip.h"
#include "IntCtrl_Ip.h"
#include "FreeRTOS.h"

/* ---- LPUART instance --------------------------------------------------- */

/** @brief LPUART peripheral index used for debug output (LPUART3). */
#define LPUART_INSTANCE (3U)

/* ---- Debug logging ----------------------------------------------------- */

/** @brief Set to 1 to enable DBG_PRINT / DBG_PRINTF over LPUART3. */
#define TPM_DEBUG 1

#if TPM_DEBUG
/** @brief Send a literal string over LPUART3. */
#define DBG_PRINT(msg)                                             \
    do {                                                           \
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)(msg), \
                                strlen(msg), portMAX_DELAY);       \
    } while (0)

/** @brief printf-style debug output over LPUART3 (max 128 chars). */
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

/* ====================================================================== */
/*  TPM MMIO Register Definitions (§3.1 Transport Layer)                   */
/* ====================================================================== */

/** @brief Base address of the memory-mapped TPM peripheral in QEMU. */
#define TPM_BASE 0x40000000

/** @brief TPM_ACCESS register — request and check locality access. */
#define TPM_ACCESS \
    (*(volatile uint8_t *)(TPM_BASE + 0x0000))

/** @brief TPM_STS register — command flow control (Ready/Go/Expect/DataAvail). */
#define TPM_STS \
    (*(volatile uint32_t *)(TPM_BASE + 0x0018))

/** @brief TPM_DATA_FIFO register — byte-by-byte command/response data. */
#define TPM_DATA_FIFO \
    (*(volatile uint8_t *)(TPM_BASE + 0x0024))

/* ---- TPM_ACCESS bitmasks ----------------------------------------------- */

#define TPM_ACCESS_REQUEST_USE  0x02  /**< Write 1 to request locality. */
#define TPM_ACCESS_ACTIVE_LOCAL 0x20  /**< Read 1 when locality is granted. */

/* ---- TPM_STS bitmasks -------------------------------------------------- */

#define TPM_STS_COMMAND_READY 0x40  /**< TPM ready to receive a command.    */
#define TPM_STS_GO            0x20  /**< Write 1 to execute the command.    */
#define TPM_STS_DATA_AVAIL    0x10  /**< Response data available to read.   */
#define TPM_STS_EXPECT        0x08  /**< TPM expects more command bytes.    */

#endif /* TPM_PLATFORM_H */

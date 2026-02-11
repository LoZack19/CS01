/*
 * Lpuart_Uart_Ip.h — Fake/stub header for the NXP LPUART UART IP driver.
 *
 * Provides only the types and declarations actually referenced by the
 * firmware so that the code can be compiled outside the real NXP SDK.
 */
#ifndef LPUART_UART_IP_H
#define LPUART_UART_IP_H

#include <stdint.h>
#include <stddef.h>

/* Return status type used by the UART driver */
typedef enum {
    LPUART_UART_IP_STATUS_SUCCESS = 0,
    LPUART_UART_IP_STATUS_ERROR,
    LPUART_UART_IP_STATUS_BUSY,
    LPUART_UART_IP_STATUS_TIMEOUT,
} Lpuart_Uart_Ip_StatusType;

/* Hardware configuration (opaque for our purposes) */
typedef struct {
    uint32_t dummy; /* placeholder */
} Lpuart_Uart_Ip_UserConfigType;

/* Pre-built configuration instance referenced in main.c */
extern const Lpuart_Uart_Ip_UserConfigType Lpuart_Uart_Ip_xHwConfigPB_3;

/* Initialise a LPUART instance with the given configuration */
static inline void Lpuart_Uart_Ip_Init(uint32_t instance,
                                       const Lpuart_Uart_Ip_UserConfigType *config)
{
    (void)instance;
    (void)config;
}

/* Synchronously send data over LPUART.
 * Returns LPUART_UART_IP_STATUS_SUCCESS on success. */
static inline Lpuart_Uart_Ip_StatusType
Lpuart_Uart_Ip_SyncSend(uint32_t instance, const uint8_t *txBuff,
                         uint32_t txSize, uint32_t timeout)
{
    (void)instance;
    (void)txBuff;
    (void)txSize;
    (void)timeout;
    return LPUART_UART_IP_STATUS_SUCCESS;
}

#endif /* LPUART_UART_IP_H */

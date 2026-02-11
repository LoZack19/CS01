/*
 * S32K358.h — Fake/stub header for NXP S32K358 MCU definitions.
 *
 * Provides only the symbols actually referenced by the firmware so that
 * the code can be compiled (or analysed) outside the real NXP SDK.
 */
#ifndef S32K358_H
#define S32K358_H

#include <stdint.h>

/* IRQ numbers used in the firmware */
typedef enum {
    LPUART0_IRQn = 33,
    LPUART1_IRQn = 34,
    LPUART2_IRQn = 35,
    LPUART3_IRQn = 36,
} IRQn_Type;

#endif /* S32K358_H */

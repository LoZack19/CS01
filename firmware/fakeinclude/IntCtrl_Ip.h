/*
 * IntCtrl_Ip.h — Fake/stub header for the NXP Interrupt Controller IP driver.
 *
 * Provides only the types and declarations actually referenced by the
 * firmware so that the code can be compiled outside the real NXP SDK.
 */
#ifndef INTCTRL_IP_H
#define INTCTRL_IP_H

#include <stdint.h>
#include "S32K358.h" /* for IRQn_Type */

/* Interrupt controller configuration (opaque for our purposes) */
typedef struct {
    uint32_t dummy; /* placeholder */
} IntCtrl_Ip_CtrlConfigType;

/* Pre-built configuration instance referenced in main.c */
extern const IntCtrl_Ip_CtrlConfigType IntCtrlConfig_0;

/* Initialise the interrupt controller with the given configuration */
static inline void IntCtrl_Ip_Init(const IntCtrl_Ip_CtrlConfigType *config)
{
    (void)config;
}

/* Enable a specific IRQ */
static inline void IntCtrl_Ip_EnableIrq(IRQn_Type irqn)
{
    (void)irqn;
}

#endif /* INTCTRL_IP_H */

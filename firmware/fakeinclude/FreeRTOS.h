/*
 * FreeRTOS.h — Fake/stub header for FreeRTOS.
 *
 * Provides only the macros actually referenced by the firmware so that
 * the code can be compiled outside a real FreeRTOS environment.
 */
#ifndef FREERTOS_H
#define FREERTOS_H

#include <stdint.h>
#include <limits.h>

/* portMAX_DELAY is used as a "wait forever" timeout value.
 * Real FreeRTOS defines it based on configUSE_16_BIT_TICKS.
 * We assume 32-bit ticks (the common case). */
#ifndef portMAX_DELAY
#define portMAX_DELAY 0xFFFFFFFFUL
#endif

#endif /* FREERTOS_H */

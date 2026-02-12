/*
 * tpm_assert.c — Test assertion framework implementation.
 */

#include "tpm_platform.h"
#include "tpm_assert.h"

/* ---- TPM_RC to string -------------------------------------------------- */

const char *string_from_TPM_RC(TPM_RC rc) {
    switch (rc) {
    /*
     * Important: several TPM_RC_* macros in our header are *modifiers* or
     * *aliases* (e.g. TPM_RC_H, TPM_RC_P, TPM_RC_1, RC_VER1, TPM_RCS_*).
     * They intentionally share integer values and are not distinguishable
     * at runtime, so they must NOT appear as distinct switch labels.
     */
    case TPM_RC_SUCCESS:
        return "TPM_RC_SUCCESS";
    case TPM_RC_BAD_TAG:
        return "TPM_RC_BAD_TAG";

    /* Ver1 family (RC_VER1 is a base, not a standalone code) */
    case TPM_RC_FAILURE:
        return "TPM_RC_FAILURE";
    case TPM_RC_COMMAND_SIZE:
        return "TPM_RC_COMMAND_SIZE";
    case TPM_RC_COMMAND_CODE:
        return "TPM_RC_COMMAND_CODE";
    case TPM_RC_NV_RANGE:
        return "TPM_RC_NV_RANGE";
    case TPM_RC_NV_LOCKED:
        return "TPM_RC_NV_LOCKED";
    case TPM_RC_NV_AUTHORIZATION:
        return "TPM_RC_NV_AUTHORIZATION";
    case TPM_RC_NV_UNINITIALIZED:
        return "TPM_RC_NV_UNINITIALIZED";
    case TPM_RC_NV_SPACE:
        return "TPM_RC_NV_SPACE";
    case TPM_RC_NV_DEFINED:
        return "TPM_RC_NV_DEFINED";

    /* Format-1 style base codes */
    case TPM_RC_ATTRIBUTES:
        return "TPM_RC_ATTRIBUTES";
    case TPM_RC_HASH:
        return "TPM_RC_HASH";
    case TPM_RC_VALUE:
        return "TPM_RC_VALUE";
    case TPM_RC_HIERARCHY:
        return "TPM_RC_HIERARCHY";
    case TPM_RC_MODE:
        return "TPM_RC_MODE";
    case TPM_RC_HANDLE:
        return "TPM_RC_HANDLE";
    case TPM_RCS_SIZE:
        return "TPM_RCS_SIZE";
    case TPM_RC_SIGNATURE:
        return "TPM_RC_SIGNATURE";
    case TPM_RC_KEY:
        return "TPM_RC_KEY";
    case TPM_RC_KEY_SIZE:
        return "TPM_RC_KEY_SIZE";
    case TPM_RC_BINDING:
        return "TPM_RC_BINDING";
    case TPM_RC_SEQUENCE:
        return "TPM_RC_SEQUENCE";

    default:
        return "UNKNOWN_RC";
    }
}

/* ---- Assertion counters ------------------------------------------------ */

int assert_count = 0;
int assert_failures = 0;

/* ---- assert() ---------------------------------------------------------- */

void assert(bool expression, const char *msg, const char *expected,
            const char *actual) {
    if (!expression) {
        if (msg != NULL) {
            Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)msg,
                                    strlen(msg), portMAX_DELAY);
        }

        // Expected: <exp>, got: <got>
        if (expected != NULL) {
            Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE,
                                    (uint8_t *)"Expected: ", 10, portMAX_DELAY);

            Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)expected,
                                    strlen(expected), portMAX_DELAY);
        }

        if (actual != NULL) {
            Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)", got: ", 7,
                                    portMAX_DELAY);

            Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)actual,
                                    strlen(actual), portMAX_DELAY);
        }

        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"\n", 1,
                                portMAX_DELAY);

        assert_failures++;
    }
    assert_count++;
}

/* ---- assert_report() --------------------------------------------------- */

void assert_report(void) {
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"Assert Report\n", 14,
                            portMAX_DELAY);

    char buffer[50];
    int len =
        snprintf(buffer, sizeof(buffer), "Total asserts: %d\n", assert_count);
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)buffer, len,
                            portMAX_DELAY);

    len = snprintf(buffer, sizeof(buffer), "Failed asserts: %d\n",
                   assert_failures);
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)buffer, len,
                            portMAX_DELAY);

    if (assert_failures == 0) {
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE,
                                (uint8_t *)"All tests passed!\n", 18,
                                portMAX_DELAY);
    } else {
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE,
                                (uint8_t *)"Some tests failed!\n", 19,
                                portMAX_DELAY);
    }
}

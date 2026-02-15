/**
 * @file main.c
 * @brief Entry point and top-level test orchestration for the TPM firmware.
 *
 * Execution flow:
 *   1. main() initialises IntCtrl and LPUART3 for debug output.
 *   2. tpm_test() requests TPM locality, runs the state-machine startup,
 *      then dispatches enabled smoke tests (tpm_test_smoke.c) and the
 *      key-management suite (tpm_test_keymgmt.c).
 *   3. State-machine shutdown is performed last.
 *   4. assert_report() prints pass/fail totals.
 *
 * Test selection is controlled at compile time by tpm_tests_config.h.
 */

#include "tpm_platform.h"
#include "tpm_assert.h"
#include "tpm_driver.h"
#include "tpm2_spec_protocol.h"
#include "tpm_tests_config.h"
#include "IntCtrl_Ip.h"

/* ---- Smoke test declarations (tpm_test_smoke.c) ---- */

#ifdef TPM_TEST_ENABLE_TRANSPORT_NEGATIVE
void TPM2_Transport_negative_tests(void);
#endif
bool TPM2_StateMachine_startup_test(void);
void TPM2_StateMachine_shutdown_test(void);
#ifdef TPM_TEST_ENABLE_NV_DEFINE
void TPM2_NV_DefineSpace_test(void);
#endif
#ifdef TPM_TEST_ENABLE_NV_WRITE_READ
void TPM2_NV_WriteRead_test(void);
#endif
#ifdef TPM_TEST_ENABLE_HASH
void TPM2_Hash_smoke_test(void);
#endif
#ifdef TPM_TEST_ENABLE_ERROR_HANDLING
void TPM2_Error_handling_tests(void);
#endif
#ifdef TPM_TEST_ENABLE_SIGN
void TPM2_Sign_smoke_test(void);
#endif
#ifdef TPM_TEST_ENABLE_VERIFY_SIGNATURE
void TPM2_VerifySignature_smoke_test(void);
#endif
#ifdef TPM_TEST_ENABLE_ENCRYPT_DECRYPT2
void TPM2_EncryptDecrypt2_smoke_test(void);
#endif
#ifdef TPM_TEST_ENABLE_RSA_ENCRYPT_DECRYPT
void TPM2_RSA_EncryptDecrypt_smoke_test(void);
#endif

/* ---- Key management suite declaration (tpm_test_keymgmt.c) ---- */
void TPM2_KeyManagement_test_suite(void);

/**
 * @brief Top-level test orchestrator.
 *
 * Requests TPM locality, runs Startup, dispatches all enabled test
 * groups in order, then performs Shutdown.  If Startup fails, all
 * subsequent tests are skipped.
 */
void tpm_test(void) {
    tpm_wait_access();
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE,
                            (uint8_t *)"[INFO] TPM access granted\n", 26,
                            portMAX_DELAY);

    if (!TPM2_StateMachine_startup_test()) {
        DBG_PRINT("[FATAL] State machine startup failed. Skipping all "
                  "remaining TPM tests.\n");
        return;
    }

    /* GROUP A - Transport & framing negative tests (S.1) */
#ifdef TPM_TEST_ENABLE_TRANSPORT_NEGATIVE
    TPM2_Transport_negative_tests();
#endif

#ifdef TPM_TEST_ENABLE_NV_DEFINE
    TPM2_NV_DefineSpace_test();
#else
    DBG_PRINT("[TEST] TPM2_NV_DefineSpace: SKIPPED (not enabled)\n");
#endif

#ifdef TPM_TEST_ENABLE_NV_WRITE_READ
    TPM2_NV_WriteRead_test();
#else
    DBG_PRINT("[TEST] TPM2_NV_WriteRead: SKIPPED (not enabled)\n");
#endif

#ifdef TPM_TEST_ENABLE_HASH
    TPM2_Hash_smoke_test();
#else
    DBG_PRINT("[TEST] TPM2_Hash: SKIPPED (not enabled)\n");
#endif

    /* GROUP G - Error handling tests (S.9) */
#ifdef TPM_TEST_ENABLE_ERROR_HANDLING
    TPM2_Error_handling_tests();
#endif

#ifdef TPM_TEST_ENABLE_SIGN
    TPM2_Sign_smoke_test();
#else
    DBG_PRINT("[TEST] TPM2_Sign: SKIPPED (not enabled)\n");
#endif

#ifdef TPM_TEST_ENABLE_VERIFY_SIGNATURE
    TPM2_VerifySignature_smoke_test();
#else
    DBG_PRINT("[TEST] TPM2_VerifySignature: SKIPPED (not enabled)\n");
#endif

#ifdef TPM_TEST_ENABLE_ENCRYPT_DECRYPT2
    TPM2_EncryptDecrypt2_smoke_test();
#else
    DBG_PRINT("[TEST] TPM2_EncryptDecrypt2: SKIPPED (not enabled)\n");
#endif

#ifdef TPM_TEST_ENABLE_RSA_ENCRYPT_DECRYPT
    TPM2_RSA_EncryptDecrypt_smoke_test();
#else
    DBG_PRINT("[TEST] TPM2_RSA_EncryptDecrypt: SKIPPED (not enabled)\n");
#endif

    /* Key Management Tests */
    TPM2_KeyManagement_test_suite();

    TPM2_StateMachine_shutdown_test();
}

/**
 * @brief Firmware entry point — hardware init, run tests, report results.
 *
 * Initialises the interrupt controller and LPUART3, then enters an
 * infinite loop after printing the assertion summary.
 */
int main(void) {
    IntCtrl_Ip_Init(&IntCtrlConfig_0);
    IntCtrl_Ip_EnableIrq(LPUART3_IRQn);

    Lpuart_Uart_Ip_Init(LPUART_INSTANCE, &Lpuart_Uart_Ip_xHwConfigPB_3);
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE,
                            (uint8_t *)"[INFO] Starting TPM Test\n", 25,
                            portMAX_DELAY);

    tpm_test();

    assert_report();

    while (1)
        ;

    return 0;
}

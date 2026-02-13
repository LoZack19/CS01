/*
 * main.c - Entry point and top-level test orchestration.
 *
 * All test logic lives in:
 *   - tpm_test_smoke.c   (standalone command smoke tests)
 *   - tpm_test_keymgmt.c (key lifecycle & verification property tests)
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

/* ================================================================
 * tpm_test - top-level test orchestrator
 * ================================================================ */
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

/* ================================================================
 * main - hardware init, run tests, report results
 * ================================================================ */
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

#ifndef TPM_ASSERT_H
#define TPM_ASSERT_H

/*
 * tpm_assert.h — Lightweight test-assertion framework for TPM firmware tests.
 *
 * Provides:
 *   - string_from_TPM_RC()  — human-readable RC strings
 *   - assert()              — test assertion with expected/actual reporting
 *   - assert_report()       — summary at test-run end
 */

#include <stdbool.h>
#include "tpm2_spec_protocol.h"

extern int assert_count;
extern int assert_failures;

const char *string_from_TPM_RC(TPM_RC rc);

void assert(bool expression, const char *msg, const char *expected,
            const char *actual);

void assert_report(void);

#endif /* TPM_ASSERT_H */

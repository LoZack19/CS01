/**
 * @file tpm_assert.h
 * @brief Lightweight test-assertion framework for TPM firmware tests.
 *
 * Provides three facilities used throughout the test suites:
 *   - string_from_TPM_RC()  — human-readable TPM_RC strings for diagnostics
 *   - assert()              — test assertion with expected/actual reporting
 *   - assert_report()       — end-of-run summary (pass/fail count)
 *
 * Output is sent over LPUART3 so the QEMU host can capture it.
 */

#ifndef TPM_ASSERT_H
#define TPM_ASSERT_H

#include <stdbool.h>
#include "tpm2_spec_protocol.h"

/** @brief Total number of assertions evaluated so far. */
extern int assert_count;

/** @brief Number of assertions that evaluated to false. */
extern int assert_failures;

/**
 * @brief Return a human-readable string for the given TPM response code.
 * @param rc  A TPM_RC value (may include modifiers).
 * @return    Static string literal such as "TPM_RC_SUCCESS".
 */
const char *string_from_TPM_RC(TPM_RC rc);

/**
 * @brief Evaluate a test assertion.
 *
 * On failure the diagnostic message, expected, and actual strings
 * are printed via LPUART3, and @c assert_failures is incremented.
 * Every call increments @c assert_count regardless of result.
 *
 * @param expression Boolean condition to test.
 * @param msg        Human-readable description of the assertion.
 * @param expected   Expected-value string (may be NULL).
 * @param actual     Actual-value string   (may be NULL).
 */
void assert(bool expression, const char *msg, const char *expected,
            const char *actual);

/**
 * @brief Print the final test summary (total / failed / pass/fail verdict).
 */
void assert_report(void);

#endif /* TPM_ASSERT_H */

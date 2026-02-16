/**
 * @file tpm_state_machine.c
 * @brief TPM 2.0 state-machine implementation.
 *
 * Implements the TPM lifecycle management commands per the TPM 2.0
 * specification Part 3 (Commands).  The state machine enforces:
 *   - **Startup gating**: only Startup, GetCapability, and GetTestResult
 *     are accepted before TPM2_Startup() completes.
 *   - **Failure-mode isolation**: most commands are rejected while the
 *     TPM is in failure mode.
 *   - **Field-Upgrade Mode (FUM)**: restricts the command set to
 *     FieldUpgradeData, GetCapability, and GetTestResult.
 *
 * Each @c TPM2_*_SM function operates on the per-device
 * @ref S32k358TPMState, keeping all mutable state inside the QEMU
 * device object.
 *
 * @see s32k358_tpm.c  for command dispatch that calls these helpers.
 * @see tpm2_spec_protocol.h  for type and constant definitions.
 */

#include "qemu/osdep.h"
#include "include/hw/misc/s32k358_tpm.h"

/**
 * @brief Build the TPMA_STARTUP_CLEAR attribute bitmask.
 *
 * Reads hierarchy-enable flags and orderly/read-only state from the
 * device context and packs them into a single uint32_t in the layout
 * defined by the TPM 2.0 spec (Part 2, Table 34).
 *
 * @param[in] s  Device state.
 * @return Packed TPMA_STARTUP_CLEAR value.
 */
static uint32_t tpm_startup_clear_value(S32k358TPMState *s) {
    uint32_t value = 0;

    if (s->gc.phEnableNV) {
        value |= TPMA_STARTUP_CLEAR_PH_ENABLE;
    }
    if (s->gc.shEnable) {
        value |= TPMA_STARTUP_CLEAR_SH_ENABLE;
    }
    if (s->gc.ehEnable) {
        value |= TPMA_STARTUP_CLEAR_EH_ENABLE;
    }
    if (s->read_only_mode) {
        value |= TPMA_STARTUP_CLEAR_READ_ONLY;
    }
    if (s->orderly_shutdown) {
        value |= TPMA_STARTUP_CLEAR_ORDERLY;
    }

    return value;
}

/**
 * @brief Build the TPMA_PERMANENT attribute bitmask.
 *
 * Currently maps the @c read_only_mode flag to
 * @c TPMA_PERMANENT_DISABLE_CLEAR.
 *
 * @param[in] s  Device state.
 * @return Packed TPMA_PERMANENT value.
 */
static uint32_t tpm_permanent_value(S32k358TPMState *s) {
    uint32_t value = 0;

    if (s->read_only_mode) {
        value |= TPMA_PERMANENT_DISABLE_CLEAR;
    }

    return value;
}

/**
 * @brief Build the TPMA_MODES attribute bitmask.
 *
 * Sets @c TPMA_MODES_FIPS_140_2 when the platform algorithm is not
 * @c TPM_ALG_NULL, indicating a FIPS 140-2 compliant configuration.
 *
 * @param[in] s  Device state.
 * @return Packed TPMA_MODES value.
 */
static uint32_t tpm_modes_value(S32k358TPMState *s) {
    uint32_t value = 0;

    if (s->gc.platformAlg != TPM_ALG_NULL) {
        value |= TPMA_MODES_FIPS_140_2;
    }

    return value;
}

/* Reset all state-machine fields to power-on defaults. */
void tpm_state_machine_reset(S32k358TPMState *s) {
    s->initialized = false;
    s->in_failure_mode = false;
    s->in_fum_mode = false;
    s->orderly_shutdown = false;
    s->startup_clear_required = false;
    s->read_only_mode = false;
    s->last_shutdown_type = TPM_SU_CLEAR;
    s->self_test_result = TPM_RC_SUCCESS;
    s->self_test_done = false;
}

/* Gate a command against the current TPM mode. */
bool tpm_command_allowed_in_current_mode(S32k358TPMState *s, TPM_CC cc,
                                         TPM_RC *rc_out) {
    if (s->in_failure_mode) {
        if (cc == TPM_CC_GetTestResult || cc == TPM_CC_GetCapability) {
            return true;
        }
        *rc_out = TPM_RC_FAILURE;
        return false;
    }

    if (s->in_fum_mode) {
        if (cc == TPM_CC_FieldUpgradeData || cc == TPM_CC_GetCapability ||
            cc == TPM_CC_GetTestResult) {
            return true;
        }
        *rc_out = TPM_RC_UPGRADE;
        return false;
    }

    if (!s->initialized) {
        if (cc == TPM_CC_Startup || cc == TPM_CC_GetCapability ||
            cc == TPM_CC_GetTestResult) {
            return true;
        }
        *rc_out = TPM_RC_INITIALIZE;
        return false;
    }

    return true;
}

/* Execute TPM2_Startup (state-machine layer). */
TPM_RC TPM2_Startup_SM(S32k358TPMState *s, Startup_In *in) {
    if (in->startupType != TPM_SU_CLEAR && in->startupType != TPM_SU_STATE) {
        return TPM_RC_VALUE;
    }

    if (s->initialized) {
        return TPM_RC_INITIALIZE;
    }

    if (s->startup_clear_required && in->startupType != TPM_SU_CLEAR) {
        return TPM_RC_REBOOT;
    }

    if (in->startupType == TPM_SU_STATE) {
        if (!s->orderly_shutdown || s->last_shutdown_type != TPM_SU_STATE) {
            return TPM_RC_NV_UNINITIALIZED;
        }
    }

    if (in->startupType == TPM_SU_CLEAR) {
        s->gc.shEnable = shEnable_RESET;
        s->gc.ehEnable = ehEnable_RESET;
        s->gc.phEnableNV = phEnableNV_RESET;
        s->in_failure_mode = false;
        s->in_fum_mode = false;
    }

    s->initialized = true;
    s->orderly_shutdown = false;
    s->startup_clear_required = false;

    return TPM_RC_SUCCESS;
}

/* Execute TPM2_Shutdown (state-machine layer). */
TPM_RC TPM2_Shutdown_SM(S32k358TPMState *s, Shutdown_In *in) {
    if (in->shutdownType != TPM_SU_CLEAR && in->shutdownType != TPM_SU_STATE) {
        return TPM_RC_VALUE;
    }

    if (!s->initialized) {
        return TPM_RC_INITIALIZE;
    }

    s->orderly_shutdown = true;
    s->last_shutdown_type = in->shutdownType;

    return TPM_RC_SUCCESS;
}

/* Execute TPM2_SelfTest (state-machine layer). */
TPM_RC TPM2_SelfTest_SM(S32k358TPMState *s, SelfTest_In *in) {
    if (!s->initialized) {
        return TPM_RC_INITIALIZE;
    }

    if (in->fullTest != 0 && in->fullTest != 1) {
        return TPM_RC_VALUE;
    }

    s->self_test_done = true;
    s->self_test_result = TPM_RC_SUCCESS;

    if (s->self_test_result != TPM_RC_SUCCESS) {
        s->in_failure_mode = true;
        return TPM_RC_FAILURE;
    }

    return TPM_RC_SUCCESS;
}

/* Execute TPM2_GetTestResult (state-machine layer). */
TPM_RC TPM2_GetTestResult_SM(S32k358TPMState *s, GetTestResult_Out *out) {
    out->outData.size = 0;
    out->testResult = s->self_test_result;
    return TPM_RC_SUCCESS;
}

/* Execute TPM2_GetCapability (state-machine layer). */
TPM_RC TPM2_GetCapability_SM(S32k358TPMState *s, GetCapability_In *in,
                             GetCapability_Out *out) {
    uint32_t value;

    if (in->capability != TPM_CAP_TPM_PROPERTIES) {
        return TPM_RC_VALUE;
    }

    switch (in->property) {
    case TPM_PT_PERMANENT:
        value = tpm_permanent_value(s);
        break;
    case TPM_PT_STARTUP_CLEAR:
        value = tpm_startup_clear_value(s);
        break;
    case TPM_PT_MODES:
        value = tpm_modes_value(s);
        break;
    default:
        return TPM_RC_VALUE;
    }

    out->moreData = 0;
    out->property = in->property;
    out->value = value;

    return TPM_RC_SUCCESS;
}

/* Execute TPM2_FieldUpgradeStart (state-machine layer). */
TPM_RC TPM2_FieldUpgradeStart_SM(S32k358TPMState *s) {
    if (!s->initialized) {
        return TPM_RC_INITIALIZE;
    }

    if (s->in_failure_mode) {
        return TPM_RC_FAILURE;
    }

    s->in_fum_mode = true;
    return TPM_RC_SUCCESS;
}

/* Execute TPM2_FieldUpgradeData (state-machine layer). */
TPM_RC TPM2_FieldUpgradeData_SM(S32k358TPMState *s, FieldUpgradeData_In *in) {
    if (!s->in_fum_mode) {
        return TPM_RC_UPGRADE;
    }

    if (in->fuData.size > sizeof(in->fuData.buffer)) {
        return TPM_RC_VALUE;
    }

    if (in->fuData.size > 0 && in->fuData.buffer[0] == 0xFF) {
        s->in_fum_mode = false;
        s->initialized = false;
        s->startup_clear_required = true;
    }

    return TPM_RC_SUCCESS;
}

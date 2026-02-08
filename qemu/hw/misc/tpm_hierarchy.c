/*
 * tpm_hierarchy.c – Hierarchy-related helpers for the TPM model.
 *
 * Class: Hierarchy
 * Functions: HierarchyGetPrimarySeed, HierarchyNormalizeHandle,
 *            EntityGetHierarchy
 *
 * Reference: ms-tpm-20-ref  Hierarchy.c, Entity.c
 */

#include "hw/misc/s32k358_tpm.h"
#include "hw/misc/tpm_create_primary.h"
#include <string.h>

/*
 * The S32k358TPMState stores per-hierarchy seeds.  To access them we
 * need a pointer to the device state.  In a QEMU device model we can
 * keep a module-level pointer that is set once during device realize.
 *
 * This is set from the main device model file (s32k358_tpm.c) by
 * calling tpm_hierarchy_set_state().
 */
static S32k358TPMState *g_tpm_state;

void tpm_hierarchy_set_state(S32k358TPMState *s)
{
    g_tpm_state = s;
}

/*
 * HierarchyGetPrimarySeed – Return the primary seed for a given hierarchy.
 *
 * The hierarchy handle identifies which seed to use:
 *   TPM_RH_ENDORSEMENT => endorsement seed
 *   TPM_RH_PLATFORM    => platform seed
 *   TPM_RH_OWNER       => owner (storage) seed
 *   TPM_RH_NULL        => null seed
 *
 * FW-limited and SVN-limited hierarchy handles are normalised to their
 * base hierarchy first.
 *
 * Reference: ms-tpm-20-ref Hierarchy.c HierarchyGetPrimarySeed()
 */
TPM_RC HierarchyGetPrimarySeed(TPM_HANDLE hierarchy, TPM2B_SEED *seed)
{
    TPM_HANDLE base;
    TPM2B_SEED *src;

    if (g_tpm_state == NULL) {
        /* Fallback: fill with a deterministic dummy value. */
        seed->size = 32;
        memset(seed->buffer, 0xAB, 32);
        return TPM_RC_SUCCESS;
    }

    /* Normalise FW-/SVN-limited handles to the base hierarchy. */
    base = HierarchyNormalizeHandle(hierarchy);

    switch (base) {
    case TPM_RH_ENDORSEMENT:
        src = &g_tpm_state->endorsement_seed;
        break;
    case TPM_RH_PLATFORM:
        src = &g_tpm_state->platform_seed;
        break;
    case TPM_RH_OWNER:
        src = &g_tpm_state->owner_seed;
        break;
    case TPM_RH_NULL:
    default:
        src = &g_tpm_state->null_seed;
        break;
    }

    /* Copy the seed.  If it has not been initialised yet (size == 0),
     * generate a deterministic placeholder so the command doesn't fail. */
    if (src->size == 0) {
        seed->size = 32;
        memset(seed->buffer, 0xAB, 32);
    } else {
        seed->size = src->size;
        memcpy(seed->buffer, src->buffer, src->size);
    }

    return TPM_RC_SUCCESS;
}

/*
 * HierarchyNormalizeHandle – Map FW-/SVN-limited hierarchy handles to
 * the corresponding base hierarchy.
 *
 * Reference: ms-tpm-20-ref Hierarchy.c
 */
TPM_HANDLE HierarchyNormalizeHandle(TPM_HANDLE handle)
{
    /* FW-limited handles */
    switch (handle) {
    case TPM_RH_FW_OWNER:
        return TPM_RH_OWNER;
    case TPM_RH_FW_ENDORSEMENT:
        return TPM_RH_ENDORSEMENT;
    case TPM_RH_FW_PLATFORM:
        return TPM_RH_PLATFORM;
    case TPM_RH_FW_NULL:
        return TPM_RH_NULL;
    default:
        break;
    }

    /* SVN-limited handles: the top 16 bits encode hierarchy base,
     * the low 16 bits are the SVN value. */
    switch (handle & 0xFFFF0000) {
    case TPM_RH_SVN_OWNER_BASE:
        return TPM_RH_OWNER;
    case TPM_RH_SVN_ENDORSEMENT_BASE:
        return TPM_RH_ENDORSEMENT;
    case TPM_RH_SVN_PLATFORM_BASE:
        return TPM_RH_PLATFORM;
    case TPM_RH_SVN_NULL_BASE:
        return TPM_RH_NULL;
    default:
        break;
    }

    return handle;
}

/*
 * EntityGetHierarchy – Determine the hierarchy to which a handle belongs.
 *
 * For permanent handles (0x40xxxxxx) we return the hierarchy itself
 * (or the normalised version for FW/SVN handles).
 * For transient objects (0x80xxxxxx) and persistent objects (0x81xxxxxx)
 * we return TPM_RH_OWNER by convention (in a real TPM the hierarchy
 * is stored inside the OBJECT).
 * NV indices (0x01xxxxxx) return TPM_RH_OWNER.
 *
 * Reference: ms-tpm-20-ref Entity.c EntityGetHierarchy()
 */
TPMI_RH_HIERARCHY EntityGetHierarchy(TPM_HANDLE handle)
{
    TPM_HT handleType = (TPM_HT)(handle >> HR_SHIFT);

    switch (handleType) {
    case 0x40: /* TPM_HT_PERMANENT */
    {
        TPM_HANDLE base = HierarchyNormalizeHandle(handle);
        switch (base) {
        case TPM_RH_OWNER:
        case TPM_RH_ENDORSEMENT:
        case TPM_RH_PLATFORM:
        case TPM_RH_NULL:
            return base;
        default:
            return TPM_RH_NULL;
        }
    }
    case 0x80: /* TPM_HT_TRANSIENT  */
    case 0x81: /* TPM_HT_PERSISTENT */
        /*
         * In a full implementation the hierarchy is read from the
         * OBJECT structure.  For this simplified model we assume the
         * owner hierarchy.
         */
        return TPM_RH_OWNER;
    case TPM_HT_NV_INDEX:
        return TPM_RH_OWNER;
    default:
        return TPM_RH_NULL;
    }
}

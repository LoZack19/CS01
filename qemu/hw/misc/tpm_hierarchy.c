/**
 * @file   tpm_hierarchy.c
 * @brief  Hierarchy-related helpers for the TPM model.
 *
 * Manages hierarchy seeds and handle normalization.  The TPM 2.0 spec
 * defines four hierarchies (Owner, Endorsement, Platform, Null), each
 * with its own primary seed.  Additional FW-limited and SVN-limited
 * handles are mapped to their base hierarchy.
 *
 * @see ms-tpm-20-ref Hierarchy.c, Entity.c
 * @see TPM 2.0 Part 1 Section 13 – Hierarchy
 */

#include "hw/misc/s32k358_tpm.h"
#include "hw/misc/tpm_create_primary.h"
#include <string.h>

/**
 * @brief Module-level pointer to the device state.
 *
 * Set once from the device @c realize callback via
 * @c tpm_hierarchy_set_state().  Provides access to
 * per-hierarchy seeds stored in @c S32k358TPMState.
 */
static S32k358TPMState *g_tpm_state;

/**
 * @brief Register the device state for hierarchy seed look-ups.
 *
 * Must be called exactly once from @c s32k358_tpm_realize().
 *
 * @param[in] s  Pointer to the device instance.
 */
void tpm_hierarchy_set_state(S32k358TPMState *s)
{
    g_tpm_state = s;
}

/**
 * @brief Return the primary seed for a given hierarchy.
 *
 * Maps the hierarchy handle to the corresponding seed stored in
 * @c S32k358TPMState.  FW-limited and SVN-limited handles are
 * normalised to their base hierarchy first.
 *
 * | Handle               | Seed              |
 * |----------------------|-------------------|
 * | @c TPM_RH_ENDORSEMENT| endorsement_seed  |
 * | @c TPM_RH_PLATFORM   | platform_seed     |
 * | @c TPM_RH_OWNER      | owner_seed        |
 * | @c TPM_RH_NULL       | null_seed         |
 *
 * @param[in]  hierarchy  Hierarchy handle.
 * @param[out] seed       Receives the primary seed.
 * @return @c TPM_RC_SUCCESS.
 *
 * @see ms-tpm-20-ref Hierarchy.c HierarchyGetPrimarySeed()
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

/**
 * @brief Map FW-/SVN-limited hierarchy handles to their base hierarchy.
 *
 * @param[in] handle  Raw hierarchy handle.
 * @return Base hierarchy handle, or @p handle itself if already base.
 *
 * @see ms-tpm-20-ref Hierarchy.c
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

/**
 * @brief Determine the hierarchy to which a handle belongs.
 *
 * - Permanent handles (@c 0x40xxxxxx): return the normalised hierarchy.
 * - Transient / persistent objects: return @c TPM_RH_OWNER.
 * - NV indices: return @c TPM_RH_OWNER.
 *
 * @param[in] handle  TPM handle.
 * @return Hierarchy handle.
 *
 * @see ms-tpm-20-ref Entity.c EntityGetHierarchy()
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

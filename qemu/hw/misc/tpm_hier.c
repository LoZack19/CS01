#include <stdint.h>
#include "hw/misc/tpm2_spec_protocol.h"
#include <stddef.h>
#include <stdbool.h>

typedef UINT16 NUMBYTES;

// TPM2B Types
typedef struct {
    NUMBYTES size;
    BYTE buffer[1];
} TPM2B, *P2B;

#define TPM2B_STRING(name, value)                                   \
    typedef union name##_ {                                         \
        struct {                                                    \
            UINT16 size;                                            \
            BYTE buffer[sizeof(value)];                             \
        } t;                                                        \
        TPM2B b;                                                    \
    } TPM2B_##name##_;                                              \
    const TPM2B_##name##_ name##_data = {{sizeof(value), {value}}}; \
    const TPM2B *name = &name##_data.b;

// Recommended to be the strongest in town
#define CONTEXT_INTEGRITY_HASH_ALG TPM_ALG_SHA256

TPM2B_STRING(HIERARCHY_SEED_SECRET_LABEL, "H_SEED_SECRET");

typedef enum {
    HM_NONE = 0,
    HM_FW_LIMITED,
    HM_SVN_LIMITED,
} HIERARCHY_MODIFIER_TYPE;

typedef struct {
    HIERARCHY_MODIFIER_TYPE type;
    uint16_t min_svn;
} HIERARCHY_MODIFIER;

static TPMI_RH_HIERARCHY DecomposeHandle(TPMI_RH_HIERARCHY handle,
                                         HIERARCHY_MODIFIER *modifier) {
    TPMI_RH_HIERARCHY base_hierarchy = handle;
    modifier->type = HM_NONE;

    switch (handle) {
    case TPM_RH_FW_OWNER:
        modifier->type = HM_FW_LIMITED;
        base_hierarchy = TPM_RH_OWNER;
        break;
    case TPM_RH_FW_ENDORSEMENT:
        modifier->type = HM_FW_LIMITED;
        base_hierarchy = TPM_RH_ENDORSEMENT;
        break;
    case TPM_RH_FW_PLATFORM:
        modifier->type = HM_FW_LIMITED;
        base_hierarchy = TPM_RH_PLATFORM;
        break;
    case TPM_RH_FW_NULL:
        modifier->type = HM_FW_LIMITED;
        base_hierarchy = TPM_RH_NULL;
        break;
    }

    if (modifier->type == HM_FW_LIMITED) {
        return base_hierarchy;
    }

    switch (handle & 0xFFFF0000) {
    case TPM_RH_SVN_OWNER_BASE:
        modifier->type = HM_SVN_LIMITED;
        base_hierarchy = TPM_RH_OWNER;
        break;
    case TPM_RH_SVN_ENDORSEMENT_BASE:
        modifier->type = HM_SVN_LIMITED;
        base_hierarchy = TPM_RH_ENDORSEMENT;
        break;
    case TPM_RH_SVN_PLATFORM_BASE:
        modifier->type = HM_SVN_LIMITED;
        base_hierarchy = TPM_RH_PLATFORM;
        break;
    case TPM_RH_SVN_NULL_BASE:
        modifier->type = HM_SVN_LIMITED;
        base_hierarchy = TPM_RH_NULL;
        break;
    }

    if (modifier->type == HM_SVN_LIMITED) {
        modifier->min_svn = handle & 0xFFFF;
    }

    return handle;
}

TPM_RC GetAdditionalSecret(const HIERARCHY_MODIFIER *modifier,
                           TPM2B_SEED *additional_secret,
                           const TPM2B **additional_secret_label);

void CryptKDFa(TPM_ALG_ID hashAlg, const TPM2B *key, const TPM2B *label,
               const TPM2B *contextU, const TPM2B *contextV, UINT32 bits,
               BYTE *resultKey, UINT32 *counterInOut, BOOL once);

void MemorySet(void *dest, int value, size_t size);

static TPM_RC MixAdditionalSecret(const HIERARCHY_MODIFIER *modifier,
                                  const TPM2B *base_secret_label,
                                  const TPM2B *base_secret,
                                  TPM2B *output_secret) {
    TPM_RC result = TPM_RC_SUCCESS;
    TPM2B_SEED additional_secret;
    const TPM2B *additional_secret_label = NULL;

    result = GetAdditionalSecret(modifier, &additional_secret,
                                 &additional_secret_label);
    if (result != TPM_RC_SUCCESS) {
        return result;
    }

    output_secret->size = base_secret->size;

    if (additional_secret.size == 0) {
        memcpy(output_secret->buffer, base_secret->buffer, base_secret->size);
    } else {
        CryptKDFa(CONTEXT_INTEGRITY_HASH_ALG, base_secret, base_secret_label,
                  &additional_secret, additional_secret_label,
                  output_secret->size * 8, output_secret->buffer, NULL, false);
    }
}

TPM_RC HierarchyGetPrimarySeed(TPM_HANDLE hierarchy, TPM2B_SEED *seed) {
    TPM2B_SEED *base_seed;
    HIERARCHY_MODIFIER modifier;

#error[GIOVANNI] Global TPM state 'g' is not defined

    switch (DecomposePrimarySeed(hierarchy, &modifier)) {
    case TPM_RH_PLATFORM:
        // base_seed = g->platform_seed;
        break;
    case TPM_RH_OWNER:
        // base_seed = g->owner_seed;
        break;
    case TPM_RH_ENDORSEMENT:
        // base_seed = g->endorsement_seed;
        break;
    default:
        // base_seed = g->null_seed;
        break;
    }

#warning[GIOVANNI] b field is not defined anywhere
    return MixAdditionalSecret(&modifier, HIERARCHY_SEED_SECRET_LABEL,
                               &base_seed->b, &seed->b);
}

TPM_HANDLE HierarchyNormalizeHandle(TPM_HANDLE handle);

TPMI_RH_HIERARCHY EntityGetHierarchy(TPM_HANDLE handle);
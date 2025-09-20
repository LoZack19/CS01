#include "include/hw/misc/s32k358_tpm.h"

UINT16 MemoryRemoveTrailingZeros(TPM2B_AUTH* auth)
{
    while ((auth->t.size > 0) && (auth->t.buffer[auth->t.size - 1] == 0))
    auth->t.size--;
    return auth->t.size;
}

BOOL NvIndexIsDefined(TPM_HANDLE nvHandle) {
    return (NvFindHandle(nvHandle) != 0);
}

TPM_RC NvDefineSpace(TPMI_RH_PROVISION authHandle,
    TPM2B_AUTH*       auth,
    TPMS_NV_PUBLIC*   publicInfo,
    TPM_RC            blameAuthHandle,
    TPM_RC            blameAuth,
    TPM_RC            blamePublic)
{
    TPMA_NV attributes = publicInfo->attributes;
    UINT16  nameSize;
    
    // Pick digest size for the given algorithm
    nameSize = CryptHashGetDigestSize(publicInfo->nameAlg);
    
    // If the UndefineSpaceSpecial command is not implemented, then can't have
    // an index that can only be deleted with policy
    if (IS_ATTRIBUTE(attributes, TPMA_NV, POLICY_DELETE))
    return TPM_RCS_ATTRIBUTES + blamePublic;
    
    
    // Check that the authPolicy consistent with hash algorithm
    if (publicInfo->authPolicy.t.size != 0 && publicInfo->authPolicy.t.size != nameSize)
    return TPM_RCS_SIZE + blamePublic;
    
    // Make sure that the authValue is not too large
    if (MemoryRemoveTrailingZeros(auth) > nameSize)
    return TPM_RCS_SIZE + blameAuth;
    
    // If an index is being created by the owner and shEnable is
    // clear, then we would not reach this point because ownerAuth
    // can't be given when shEnable is CLEAR. However, if phEnable
    // is SET but phEnableNV is CLEAR, we have to check here
    if (authHandle == TPM_RH_PLATFORM && gc.phEnableNV == CLEAR)
    return TPM_RCS_HIERARCHY + blameAuthHandle;
    
    // Attribute checks
    // Eliminate the unsupported types
    switch (attributes.TPM_NT) {
        // #if CC_NV_Increment == YES
        // case TPM_NT_COUNTER:
        // #endif
        // #if CC_NV_SetBits == YES
        // case TPM_NT_BITS:
        // #endif
        // #if CC_NV_Extend == YES
        // case TPM_NT_EXTEND:
        // #endif
        // #if CC_PolicySecret == YES && defined TPM_NT_PIN_PASS
        // case TPM_NT_PIN_PASS:
        // case TPM_NT_PIN_FAIL:
        // #endif
        case TPM_NT_ORDINARY:
        break;
        
        default:
            return TPM_RCS_ATTRIBUTES + blamePublic;
            break;
    }
    
    // Check that the sizes are OK based on the type
    switch (attributes.TPM_NT) {
        case TPM_NT_ORDINARY:
            // Can't exceed the allowed size for the implementation
            if (publicInfo->dataSize > MAX_NV_INDEX_SIZE)
                return TPM_RCS_SIZE + blamePublic;
            break;
        case TPM_NT_EXTEND:
            if (publicInfo->dataSize != nameSize)
                return TPM_RCS_SIZE + blamePublic;
            break;
        default:
            // Everything else needs a size of 8
            if (publicInfo->dataSize != 8)
                return TPM_RCS_SIZE + blamePublic;
            break;
    }

    // Handle other specifics
    switch (GET_TPM_NT(attributes)) {
        case TPM_NT_COUNTER:
            // Counter can't have TPMA_NV_CLEAR_STCLEAR SET (don't clear counters)
            if (IS_ATTRIBUTE(attributes, TPMA_NV, CLEAR_STCLEAR))
                return TPM_RCS_ATTRIBUTES + blamePublic;
            break;
        
        default:
            break;
    }

    // Locks may not be SET and written cannot be SET
    if (IS_ATTRIBUTE(attributes, TPMA_NV, WRITTEN)
       || IS_ATTRIBUTE(attributes, TPMA_NV, WRITELOCKED)
       || IS_ATTRIBUTE(attributes, TPMA_NV, READLOCKED))
        return TPM_RCS_ATTRIBUTES + blamePublic;

    // There must be a way to read the index.
    if (!IS_ATTRIBUTE(attributes, TPMA_NV, OWNERREAD)
       && !IS_ATTRIBUTE(attributes, TPMA_NV, PPREAD)
       && !IS_ATTRIBUTE(attributes, TPMA_NV, AUTHREAD)
       && !IS_ATTRIBUTE(attributes, TPMA_NV, POLICYREAD))
        return TPM_RCS_ATTRIBUTES + blamePublic;

    // There must be a way to write the index
    if (!IS_ATTRIBUTE(attributes, TPMA_NV, OWNERWRITE)
       && !IS_ATTRIBUTE(attributes, TPMA_NV, PPWRITE)
       && !IS_ATTRIBUTE(attributes, TPMA_NV, AUTHWRITE)
       && !IS_ATTRIBUTE(attributes, TPMA_NV, POLICYWRITE))
        return TPM_RCS_ATTRIBUTES + blamePublic;

    // An index with TPMA_NV_CLEAR_STCLEAR can't have TPMA_NV_WRITEDEFINE SET
    if (IS_ATTRIBUTE(attributes, TPMA_NV, CLEAR_STCLEAR)
       && IS_ATTRIBUTE(attributes, TPMA_NV, WRITEDEFINE))
        return TPM_RCS_ATTRIBUTES + blamePublic;

    // Make sure that the creator of the index can delete the index
    if ((IS_ATTRIBUTE(attributes, TPMA_NV, PLATFORMCREATE)
        && authHandle == TPM_RH_OWNER)
       || (!IS_ATTRIBUTE(attributes, TPMA_NV, PLATFORMCREATE)
           && authHandle == TPM_RH_PLATFORM))
        return TPM_RCS_ATTRIBUTES + blameAuthHandle;

    // If TPMA_NV_POLICY_DELETE is SET, then the index must be defined by
    // the platform
    if (IS_ATTRIBUTE(attributes, TPMA_NV, POLICY_DELETE)
       && TPM_RH_PLATFORM != authHandle)
        return TPM_RCS_ATTRIBUTES + blamePublic;

    // Make sure that the TPMA_NV_WRITEALL is not set if the index size is larger
    // than the allowed NV buffer size.
    if (publicInfo->dataSize > MAX_NV_BUFFER_SIZE
       && IS_ATTRIBUTE(attributes, TPMA_NV, WRITEALL))
        return TPM_RCS_SIZE + blamePublic;
    
    // And finally, see if the index is already defined.
    if (NvIndexIsDefined(publicInfo->nvIndex))
        return TPM_RC_NV_DEFINED;

    // Internal Data Update
    // define the space.  A TPM_RC_NV_SPACE error may be returned at this point
    return NvDefineIndex(publicInfo, auth);
}
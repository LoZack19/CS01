#include "include/hw/misc/s32k358_tpm.h"


int NvRead(S32k358TPMState *s, void *dest, uint32_t addr, size_t size)
{
   if (addr + size > s->nvmem_size)
       return 0;
   memcpy(dest, s->mem + addr, size);
   return size;
}

int Write(S32k358TPMState *s, void *src, uint32_t addr, size_t size)
{
   if (addr + size > s->nvmem_size)
       return 0;
   memcpy(s->mem + addr, src, size);
   return size;
}

NV_REF
NvWriteNvListEnd(S32k358TPMState *s, NV_REF end)
{
    // Marker is initialized with zeros
    BYTE   listEndMarker[sizeof(NV_LIST_TERMINATOR)] = {0};
    UINT64 maxCount                                  = NvReadMaxCount();
    //
    // This is a constant check that can be resolved at compile time.
    MUST_BE(sizeof(UINT64) <= sizeof(NV_LIST_TERMINATOR) - sizeof(UINT32));

    // Copy the maxCount value to the marker buffer
    MemoryCopy(&listEndMarker[sizeof(UINT32)], &maxCount, sizeof(UINT64));
    pAssert(end + sizeof(NV_LIST_TERMINATOR) <= s_evictNvEnd);

    // Write it to memory
    NvWrite(end, sizeof(NV_LIST_TERMINATOR), &listEndMarker);
    return end + sizeof(NV_LIST_TERMINATOR);
}

static NV_REF NvGetEnd(S32k358TPMState *s)
{
    size_t addr = TPM_FIRST_VALID_ADDRESS + sizeof(UINT32);
    // Step over the size field and point to the handle
    NV_ENTRY_HEADER header;
    while (NvRead(s, &header, addr, sizeof(NV_ENTRY_HEADER)) && header.size) {
        if (header.size == 0)
            return addr;
        addr += header.size + sizeof(UINT32);
    }
    return 0;
}

static UINT32 NvGetFreeBytes(S32k358TPMState *s)
{
    // This does not have an overflow issue because NvGetEnd() cannot return a value
    // that is larger than s_evictNvEnd. This is because there is always a 'stop'
    // word in the NV memory that terminates the search for the end before the
    // value can go past s_evictNvEnd.
    //return s_evictNvEnd - NvGetEnd();
    return NvGetEnd(s);
}

static TPM_RC NvAdd(UINT32 totalSize,  // IN: total size needed for this entity For
                                       //     evict object, totalSize is the same as
                                       //     bufferSize.  For NV Index, totalSize is
                                       //     bufferSize plus index data size
                    UINT32     bufferSize,  // IN: size of initial buffer
                    TPM_HANDLE handle,      // IN: optional handle
                    BYTE*      entity       // IN: initial buffer
)
{
    NV_REF newAddr;  // IN: where the new entity will start
    NV_REF nextAddr;
    //
    RETURN_IF_NV_IS_NOT_AVAILABLE;

    // Get the end of data list
    newAddr = NvGetEnd();

    // Step over the forward pointer
    nextAddr = newAddr + sizeof(UINT32);

    // Optionally write the handle. For indexes, the handle is TPM_RH_UNASSIGNED
    // so that the handle in the nvIndex is used instead of writing this value
    if(handle != TPM_RH_UNASSIGNED)
    {
        NvWrite(s, (UINT32)nextAddr, sizeof(TPM_HANDLE), &handle);
        nextAddr += sizeof(TPM_HANDLE);
    }
    // Write entity data
    NvWrite(s, (UINT32)nextAddr, bufferSize, entity);

    // Advance the pointer by the amount of the total
    nextAddr += totalSize;

    // Finish by writing the link value

    // Write the next offset (relative addressing)
    totalSize = nextAddr - newAddr;

    // Write link value
    NvWrite((UINT32)newAddr, sizeof(UINT32), &totalSize);

    // Write the list terminator
    NvWriteNvListEnd(nextAddr);

    return TPM_RC_SUCCESS;
}

static BOOL NvTestSpace(S32k358TPMState *s,
                        UINT32 size,      // IN: size of the entity to be added
                        BOOL   isIndex,   // IN: TRUE if the entity is an index
                        BOOL   isCounter  // IN: TRUE if the index is a counter
)
{
    UINT32 remainBytes = NvGetFreeBytes();
    UINT32 reserved    = sizeof(UINT32)  // size of the forward pointer
                      + sizeof(NV_LIST_TERMINATOR);

    // For NV Index, need to make sure that we do not allocate an Index if this
    // would mean that the TPM cannot allocate the minimum number of evict
    // objects.
    /* if(isIndex)
    {
        // Get the number of persistent objects allocated
        UINT32 persistentNum = NvCapGetPersistentNumber();

        // If we have not allocated the requisite number of evict objects, then we
        // need to reserve space for them.
        // NOTE: some of this is not written as simply as it might seem because
        // the values are all unsigned and subtracting needs to be done carefully
        // so that an underflow doesn't cause problems.
        if(persistentNum < MIN_EVICT_OBJECTS)
            reserved += (MIN_EVICT_OBJECTS - persistentNum) * NV_EVICT_OBJECT_SIZE;
    }
    // If this is not an index or is not a counter, reserve space for the
    // required number of counter indexes
    if(!isIndex || !isCounter)
    {
        // Get the number of counters
        UINT32 counterNum = NvCapGetCounterNumber();

        // If the required number of counters have not been allocated, reserved
        // space for the extra needed counters
        if(counterNum < MIN_COUNTER_INDICES)
            reserved += (MIN_COUNTER_INDICES - counterNum) * NV_INDEX_COUNTER_SIZE;
    }
    */
    // Check that the requested allocation will fit after making sure that there
    // will be no chance of overflow
    return ((reserved < remainBytes) && (size <= remainBytes)
            && (size + reserved <= remainBytes));
}

NV_REF
NvFindHandle(S32k358TPMState *s, TPM_HANDLE handle)
{
    size_t addr = TPM_FIRST_VALID_ADDRESS + sizeof(UINT32);
    // Step over the size field and point to the handle
    NV_ENTRY_HEADER header;
    while (NvRead(s, &header, addr, sizeof(NV_ENTRY_HEADER)) && header.size) {
        if (header.handle == handle)
            return addr;
        addr += header.size + sizeof(UINT32);
    }
    return 0;
}

UINT16 MemoryRemoveTrailingZeros(TPM2B_AUTH* auth)
{
    while ((auth->t.size > 0) && (auth->t.buffer[auth->t.size - 1] == 0))
    auth->t.size--;
    return auth->t.size;
}

NvDefineIndex(S32k358TPMState *s,
              TPMS_NV_PUBLIC* publicArea,  // IN: A template for an area to create.
              TPM2B_AUTH*     authValue    // IN: The initial authorization value
)
{
    // The buffer to be written to NV memory
    NV_INDEX nvIndex;    // the index data
    UINT16   entrySize;  // size of entry
    TPM_RC   result;
    //
    entrySize = sizeof(NV_INDEX);

    // only allocate data space for indexes that are going to be written to NV.
    // Orderly indexes don't need space.
    if(!IS_ATTRIBUTE(publicArea->attributes, TPMA_NV, ORDERLY))
        entrySize += publicArea->dataSize;
    // Check if we have enough space to create the NV Index
    // In this implementation, the only resource limitation is the available NV
    // space (and possibly RAM space.)  Other implementation may have other
    // limitation on counter or on NV slots
    if(!NvTestSpace(entrySize, TRUE, IsNvCounterIndex(publicArea->attributes)))
        return TPM_RC_NV_SPACE;

    // if the index to be defined is RAM backed, check RAM space availability
    // as well
    if(IS_ATTRIBUTE(publicArea->attributes, TPMA_NV, ORDERLY)
       && !NvRamTestSpaceIndex(publicArea->dataSize))
        return TPM_RC_NV_SPACE;
    // Copy input value to nvBuffer
    nvIndex.publicArea = *publicArea;

    // Copy the authValue
    nvIndex.authValue = *authValue;

    // Add index to NV memory
    result = NvAdd(entrySize, sizeof(NV_INDEX), TPM_RH_UNASSIGNED, (BYTE*)&nvIndex);
    /* if(result == TPM_RC_SUCCESS)
    {
        // If the data of NV Index is RAM backed, add the data area in RAM as well
        if(IS_ATTRIBUTE(publicArea->attributes, TPMA_NV, ORDERLY))
            NvAddRAM(publicArea);
    } */
    return result;
}

BOOL NvIndexIsDefined(S32k358TPMState *s, TPM_HANDLE nvHandle) {
    return (NvFindHandle(s, nvHandle) != 0);
}

TPM_RC NvDefineSpace(
    S32k358TPMState *s,
    TPMI_RH_PROVISION authHandle,
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
    if (NvIndexIsDefined(publicInfo->nvIndex, s))
        return TPM_RC_NV_DEFINED;

    // Internal Data Update
    // define the space.  A TPM_RC_NV_SPACE error may be returned at this point
    return NvDefineIndex(s, publicInfo, auth);
}



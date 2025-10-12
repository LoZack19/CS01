#include "include/hw/misc/s32k358_tpm.h"

/**
 * @brief Read into dest from addr in NV Memory of size size
 * @param[in] s TPM Device State
 * @param[in] dest Destination address
 * @param[in] addr Source address (NV Memory)
 * @param[in] size Size of the data to be read
 * @return
 *  0      -> Failure
 *  Others -> Size of the data read
 */
static
int NvRead(S32k358TPMState *s, void *dest, uint32_t addr, size_t size)
{
    if (addr + size > s->nvmem_size)
        return 0;
    memcpy(dest, s->mem + addr, size);
    return size;
}

/**
 * @brief Write src into addr in NV Memory of size size
 * @param[in] s TPM Device State
 * @param[in] src Source address
 * @param[in] addr Destination address (NV Memory)
 * @param[in] size Size of the data to be written
 * @return
 *  0      -> Failure
 *  Others -> Size of the data written
 */
static
int NvWrite(S32k358TPMState *s, void *src, uint32_t addr, size_t size)
{
    if (addr + size > s->nvmem_size)
        return 0;
    memcpy(s->mem + addr, src, size);
    return size;
}

static
UINT64 NvReadMaxCount(void) {
    return 0;
}

/**
 * @brief Write the list terminator at end
 * @param[in] s TPM Device State
 * @param[in] end Address of the first unused handle
 * @return Address after the list terminator
 */
static
NV_REF NvWriteNvListEnd(S32k358TPMState *s, NV_REF end)
{
    // Marker is initialized with zeros
    BYTE listEndMarker[sizeof(NV_LIST_TERMINATOR)] = {0};
    UINT64 maxCount = NvReadMaxCount();

    // This is a constant check that can be resolved at compile time.
    static_assert(sizeof(UINT64) <= sizeof(NV_LIST_TERMINATOR) - sizeof(UINT32));

    // Copy the maxCount value to the marker buffer
    memcpy(&listEndMarker[sizeof(UINT32)], &maxCount, sizeof(UINT64));
    assert(end + sizeof(NV_LIST_TERMINATOR) <= S32K358_TPM_NV_MEM_SIZE);

    // Write it to memory
    NvWrite(s, &listEndMarker, end, sizeof(NV_LIST_TERMINATOR));
    return end + sizeof(NV_LIST_TERMINATOR);
}

/**
 * @brief Find the address of the first unused space
 * @param[in] s TPM Device State
 * @return
 *   0      -> Failure
 *   Others -> Address of the first unused space
 */
static
NV_REF NvGetEnd(S32k358TPMState *s)
{
    // Step over the size field and point to the handle
    size_t addr = S32K358_TPM_NV_MEM_FIRST_VALID_ADDR + sizeof(UINT32);
    
    NV_ENTRY_HEADER header;
    while (NvRead(s, &header, addr, sizeof(NV_ENTRY_HEADER))) {
        if (header.size == 0)
            return addr;
        addr += header.size + sizeof(UINT32);
    }

    return 0;
}

/**
 * @brief Size of the unused space
 * @param[in] s TPM Device State
 * @return Size of the unused space
 */
static
UINT32 NvGetFreeBytes(S32k358TPMState *s)
{
    // This does not have an overflow issue because NvGetEnd() cannot return a value
    // that is larger than s_evictNvEnd. This is because there is always a 'stop'
    // word in the NV memory that terminates the search for the end before the
    // value can go past s_evictNvEnd.
    //return s_evictNvEnd - NvGetEnd();
    return S32K358_TPM_NV_MEM_SIZE - NvGetEnd(s);
}

/**
 * @brief Register a new NV_INDEX into the first unused space
 * @param[in] s TPM Device State
 * @param[in] totalSize Size of the entire entry (i.e. index and data)
 * @param[in] bufferSize Size of the initial buffer
 * @param[in] handle TPM_RH_UNASSIGNED or NV_INDEX reference
 * @param[in] entity Initial buffer (i.e. NV_INDEX witout data)
 * @return Response code TPM_RC_SUCCESS - Cannot Fail
 */
static
TPM_RC NvAdd(
    S32k358TPMState *s,
    UINT32 totalSize,
    UINT32 bufferSize,
    TPM_HANDLE handle,
    BYTE* entity)
{
    NV_REF newAddr;
    NV_REF nextAddr;

    // Get the end of data list
    newAddr = NvGetEnd(s);

    // Step over the forward pointer
    nextAddr = newAddr + sizeof(UINT32);

    // Optionally write the handle. For indexes, the handle is TPM_RH_UNASSIGNED
    // so that the handle in the nvIndex is used instead of writing this value
    if (handle != TPM_RH_UNASSIGNED) {
        NvWrite(s, &handle, (UINT32)nextAddr, sizeof(TPM_HANDLE));
        nextAddr += sizeof(TPM_HANDLE);
    }

    // Write entity data
    NvWrite(s, entity, (UINT32)nextAddr, bufferSize);

    // Advance the pointer by the amount of the total
    nextAddr += totalSize;

    // Write the next offset (relative addressing)
    totalSize = nextAddr - newAddr;

    // Write link value
    NvWrite(s, &totalSize, (UINT32)newAddr, sizeof(UINT32));

    // Write the list terminator
    NvWriteNvListEnd(s, nextAddr);

    return TPM_RC_SUCCESS;
}

/**
 * @brief Check if there is at least size bytes available
 * @param[in] s TPM Device State
 * @param[in] size Size of the entity to be added
 * @param[in] isIndex TRUE if the entry is an index
 * @param[in] isCounter TRUE if the index is a counter
 * @return TRUE if there is enough space
 */
static
BOOL NvTestSpace(S32k358TPMState *s,
                        UINT32 size,
                        BOOL   isIndex,
                        BOOL   isCounter)
{
    UINT32 remainBytes = NvGetFreeBytes(s);
    UINT32 reserved = sizeof(UINT32)  /* forward pointer size */
        + sizeof(NV_LIST_TERMINATOR); /* list terminator size */

    // Warning: Evict entries should need extra handling
    
    // Check that the requested allocation will fit after making sure that there
    // will be no chance of overflow
    return (
        (reserved < remainBytes) && (size <= remainBytes) && /* for overflow */
        (size + reserved <= remainBytes)
    );
}

/**
 * @brief Find the address of the handle
 * @param[in] s TPM Device State
 * @param[in] handle Handle we are looking for
 * @return
 *  0      -> Failure
 *  Others -> Address of the handle
 */
static
NV_REF NvFindHandle(S32k358TPMState *s, TPM_HANDLE handle)
{
    size_t addr = S32K358_TPM_NV_MEM_FIRST_VALID_ADDR + sizeof(UINT32);
   
    // Step over the size field and point to the handle
    NV_ENTRY_HEADER header;
    while (NvRead(s, &header, addr, sizeof(NV_ENTRY_HEADER)) && header.size) {
        if (header.handle == handle)
            return addr;
        addr += header.size + sizeof(UINT32);
    }

    return 0;
}

/**
 * @brief Update the size of the authorization token by discarding trailing
 *  zeros
 * @param[in] auth Authorization token
 * @return Updated size
 */
static
UINT16 MemoryRemoveTrailingZeros(TPM2B_AUTH* auth)
{
    while ((auth->size > 0) && (auth->buffer[auth->size - 1] == 0))
        auth->size--;
    return auth->size;
}

/**
 * @brief Define an uninitialized nvIndex in the first unused entry
 * @param[in] s TPM Device State
 * @param[in] publicArea A template for an area to create
 * @param[in] authValue The initial authorization value
 * @return Response code
 */
static
TPM_RC NvDefineIndex(S32k358TPMState *s,
              TPMS_NV_PUBLIC* publicArea,
              TPM2B_AUTH*     authValue)
{
    NV_INDEX nvIndex;
    UINT16   entrySize;
    TPM_RC   result;

    entrySize = sizeof(NV_INDEX);

    // Only allocate data space for indexes that are going to be written to NV.
    // Orderly indexes don't need space.
    if (!IS_ATTRIBUTE(publicArea->attributes, TPMA_NV, ORDERLY))
        entrySize += publicArea->dataSize;
    
    // Check if we have enough space to create the NV Index
    // In this implementation, the only resource limitation is the available NV
    // space (and possibly RAM space). Other implementations may have other
    // limitations on counter or on NV slots
    if (!NvTestSpace(s, entrySize, TRUE, IsNvCounterIndex(publicArea->attributes)))
        return TPM_RC_NV_SPACE;
    
    // Copy input value to nvBuffer
    nvIndex.publicArea = *publicArea;

    // Copy the authValue
    nvIndex.authValue = *authValue;

    // Add index to NV memory
    result = NvAdd(s, entrySize, sizeof(NV_INDEX), TPM_RH_UNASSIGNED, (BYTE*)&nvIndex);
    return result;
}

/**
 * @brief Check if nvHandle is already defined
 * @param[in] s TPM Device State
 * @param[in] nvHandle Handle under test
 * @return TRUE if handle is already defined
 */
static
BOOL NvIndexIsDefined(S32k358TPMState *s, TPM_HANDLE nvHandle) {
    return (NvFindHandle(s, nvHandle) != 0);
}

static
UINT16 CryptHashGetDigestSize(TPMI_ALG_HASH nameAlg) {
    return 0;
}

/**
 * @brief Defines a new Non-Volatile (NV) Index and reserves space for its data.
 * @param[in] s TPM Device State
 * @param[in] auth Authorization token
 * @param[in] publicInfo A template for an area to create
 * @param[in] blameAuthHandle Return value if AuthHandle is invalid
 * @param[in] blameAuth Return value if Auth is invalid
 * @param[in] blamePublic Return value if publicInfo is invalid
 * @return Response code
 */
TPM_RC NvDefineSpace(
    S32k358TPMState *s,
    TPMI_RH_PROVISION authHandle,
    TPM2B_AUTH* auth,
    TPMS_NV_PUBLIC* publicInfo,
    TPM_RC blameAuthHandle,
    TPM_RC blameAuth,
    TPM_RC blamePublic)
{
    TPMA_NV attributes = publicInfo->attributes;
    UINT16 nameSize;
    
    // Pick digest size for the given algorithm
    nameSize = CryptHashGetDigestSize(publicInfo->nameAlg);
    
    // If the UndefineSpaceSpecial command is not implemented, then can't have
    // an index that can only be deleted with policy
    if (IS_ATTRIBUTE(attributes, TPMA_NV, POLICY_DELETE))
        return TPM_RCS_ATTRIBUTES + blamePublic;
    
    
    // Check that the authPolicy is consistent with hash algorithm
    if (publicInfo->authPolicy.size != 0 && publicInfo->authPolicy.size != nameSize)
        return TPM_RCS_SIZE + blamePublic;
    
    // Make sure that the authValue is not too large
    if (MemoryRemoveTrailingZeros(auth) > nameSize)
        return TPM_RCS_SIZE + blameAuth;
    
    // If an index is being created by the owner and shEnable is
    // clear, then we would not reach this point because ownerAuth
    // can't be given when shEnable is CLEAR. However, if phEnable
    // is SET but phEnableNV is CLEAR, we have to check here
    if (authHandle == TPM_RH_PLATFORM && s->gc.phEnableNV == CLEAR)
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
    if (NvIndexIsDefined(s, publicInfo->nvIndex))
        return TPM_RC_NV_DEFINED;

    // Internal Data Update
    // define the space.  A TPM_RC_NV_SPACE error may be returned at this point
    return NvDefineIndex(s, publicInfo, auth);
}



#include <pthread.h>
#include "include/hw/misc/s32k358_tpm.h"

typedef struct {
    void *memory;
    size_t size;
    pthread_mutex_t lock;
} NvMemorySpace;

state_clear_data *gc;
NV_INDEX cachedNvIndex;
NV_REF cachedNvRef;

NvMemorySpace nvmem = {
    .memory = NULL,
    .size = 0,
    .lock = PTHREAD_MUTEX_INITIALIZER
};

/**
 * @brief Connect TPM memory to NvStorage module
 * @param[in] memory Reference to the device NV Memory
 * @param[in] size Size of the device NV Memory
 * @param[in] tpm_saved_state Structure holding tpm state informations saved
 *  across reboots
 * @return
 *  FALSE -> Success
 *  TRUE  -> Failure
 */
BOOL NvInit(void *memory, size_t size, state_clear_data *tpm_saved_state)
{
    pthread_mutex_lock(&nvmem.lock);

    if (memory == NULL) {
        qemu_log_mask(LOG_GUEST_ERROR, "[NV STORAGE] Invalid address for NvStorage memory");
        pthread_mutex_unlock(&nvmem.lock);
        return TRUE;
    }

    if (nvmem.memory == NULL) {
        nvmem.memory = memory;
        nvmem.size = size;
        gc = tpm_saved_state;
        pthread_mutex_unlock(&nvmem.lock);
        return FALSE;
    } else {
        qemu_log_mask(LOG_GUEST_ERROR, "[NV STORAGE] Module NvStorage cannot be used more than once");
        pthread_mutex_unlock(&nvmem.lock);
        return TRUE;
    }
}

/**
 * @brief Read into dest from addr in NV Memory of size size
 * @param[in] dest Destination address
 * @param[in] addr Source address (NV Memory)
 * @param[in] size Size of the data to be read
 * @return
 *  0      -> Failure
 *  Others -> Size of the data read
 */
static
int NvRead(void *dest, uint32_t addr, size_t size)
{
    if (addr + size > nvmem.size)
        return 0;
    memcpy(dest, nvmem.memory + addr, size);
    return size;
}

/**
 * @brief Write src into addr in NV Memory of size size
 * @param[in] src Source address
 * @param[in] addr Destination address (NV Memory)
 * @param[in] size Size of the data to be written
 * @return
 *  0      -> Failure
 *  Others -> Size of the data written
 */
static
int NvWrite(void *src, uint32_t addr, size_t size)
{
    if (addr + size > nvmem.size)
        return 0;
    memcpy(nvmem.memory + addr, src, size);
    return size;
}

static
UINT64 NvReadMaxCount(void) {
    return 0;
}

/**
 * @brief Write the list terminator at end
 * @param[in] end Address of the first unused handle
 * @return Address after the list terminator
 */
static
NV_REF NvWriteNvListEnd(NV_REF end)
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
    NvWrite(&listEndMarker, end, sizeof(NV_LIST_TERMINATOR));
    return end + sizeof(NV_LIST_TERMINATOR);
}

/**
 * @brief Find the address of the first unused space
 * @return
 *   0      -> Failure
 *   Others -> Address of the first unused space
 */
static
NV_REF NvGetEnd(void)
{
    // Step over the size field and point to the handle
    size_t addr = S32K358_TPM_NV_MEM_FIRST_VALID_ADDR + sizeof(UINT32);
    
    NV_ENTRY_HEADER header;
    while (NvRead(&header, addr, sizeof(NV_ENTRY_HEADER))) {
        if (header.size == 0)
            return addr;
        addr += header.size + sizeof(UINT32);
    }

    return 0;
}

/**
 * @brief Size of the unused space
 * @return Size of the unused space
 */
static
UINT32 NvGetFreeBytes(void)
{
    // This does not have an overflow issue because NvGetEnd() cannot return a value
    // that is larger than s_evictNvEnd. This is because there is always a 'stop'
    // word in the NV memory that terminates the search for the end before the
    // value can go past s_evictNvEnd.
    //return s_evictNvEnd - NvGetEnd();
    return S32K358_TPM_NV_MEM_SIZE - NvGetEnd();
}

/**
 * @brief Register a new NV_INDEX into the first unused space
 * @param[in] totalSize Size of the entire entry (i.e. index and data)
 * @param[in] bufferSize Size of the initial buffer
 * @param[in] handle TPM_RH_UNASSIGNED or NV_INDEX reference
 * @param[in] entity Initial buffer (i.e. NV_INDEX witout data)
 * @return Response code TPM_RC_SUCCESS - Cannot Fail
 */
static
TPM_RC NvAdd(
    UINT32 totalSize,
    UINT32 bufferSize,
    TPM_HANDLE handle,
    BYTE* entity)
{
    NV_REF newAddr;
    NV_REF nextAddr;

    // Get the end of data list
    newAddr = NvGetEnd();

    // Step over the forward pointer
    nextAddr = newAddr + sizeof(UINT32);

    // Optionally write the handle. For indexes, the handle is TPM_RH_UNASSIGNED
    // so that the handle in the nvIndex is used instead of writing this value
    if (handle != TPM_RH_UNASSIGNED) {
        NvWrite(&handle, (UINT32)nextAddr, sizeof(TPM_HANDLE));
        nextAddr += sizeof(TPM_HANDLE);
    }

    // Write entity data
    NvWrite(entity, (UINT32)nextAddr, bufferSize);

    // Advance the pointer by the amount of the total
    nextAddr += totalSize;

    // Write the next offset (relative addressing)
    totalSize = nextAddr - newAddr;

    // Write link value
    NvWrite(&totalSize, (UINT32)newAddr, sizeof(UINT32));

    // Write the list terminator
    NvWriteNvListEnd(nextAddr);

    return TPM_RC_SUCCESS;
}

/**
 * @brief Check if there is at least size bytes available
 * @param[in] size Size of the entity to be added
 * @param[in] isIndex TRUE if the entry is an index
 * @param[in] isCounter TRUE if the index is a counter
 * @return TRUE if there is enough space
 */
static
BOOL NvTestSpace(UINT32 size, BOOL isIndex, BOOL isCounter)
{
    UINT32 remainBytes = NvGetFreeBytes();
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
 * @param[in] handle Handle we are looking for
 * @return
 *  0      -> Failure
 *  Others -> Address of the handle
 */
static
NV_REF NvFindHandle(TPM_HANDLE handle)
{
    size_t addr = S32K358_TPM_NV_MEM_FIRST_VALID_ADDR + sizeof(UINT32);
   
    // Step over the size field and point to the handle
    NV_ENTRY_HEADER header;
    while (NvRead(&header, addr, sizeof(NV_ENTRY_HEADER)) && header.size) {
        if (header.handle == handle)
            return addr;
        addr += header.size + sizeof(UINT32);
    }

    return 0;
}

/**
 * @brief Reads the NV index.
 * @param[in] ref Memory location where the NV index handle is located
 * @param[out] nvIndex Pointer to the variable where the read NV index will be
 * stored.
 */
void NvReadNvIndexInfo(NV_REF    ref, 
                       NV_INDEX* nvIndex)
{
    assert(nvIndex != NULL);
    NvRead(nvIndex, ref, sizeof(NV_INDEX));
}

/**
 * @brief Gets nvIndex info.
 * @param[in] The index of the handle to be searched
 * @param[out] The location of the index.
 * @return Response code TPM_RC_SUCCESS - Cannot Fail
 */
static NV_INDEX* NvGetIndexInfo(TPM_HANDLE nvHandle, NV_REF *locator)
{
    s_cachedNvIndex.publicArea.nvIndex = TPM_RH_UNASSIGNED;
    s_cachedNvRef = NvFindHandle(nvHandle);
    if (!cachedNvRef)
        return NULL;
    NvReadNvIndexInfo(s_cachedNvRef, &s_cachedNvIndex);
    if (locator)
        *locator = s_cachedNvRef;
    return &cachedNvIndex;
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
 * @param[in] publicArea A template for an area to create
 * @param[in] authValue The initial authorization value
 * @return Response code
 */
static
TPM_RC NvDefineIndex(TPMS_NV_PUBLIC* publicArea,
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
    if (!NvTestSpace(entrySize, TRUE, IsNvCounterIndex(publicArea->attributes)))
        return TPM_RC_NV_SPACE;
    
    // Copy input value to nvBuffer
    nvIndex.publicArea = *publicArea;

    // Copy the authValue
    nvIndex.authValue = *authValue;

    // Add index to NV memory
    result = NvAdd(entrySize, sizeof(NV_INDEX), TPM_RH_UNASSIGNED, (BYTE*)&nvIndex);
    return result;
}

/**
 * @brief Check if nvHandle is already defined
 * @param[in] nvHandle Handle under test
 * @return TRUE if handle is already defined
 */
static
BOOL NvIndexIsDefined(TPM_HANDLE nvHandle) {
    return (NvFindHandle(nvHandle) != 0);
}

static
UINT16 CryptHashGetDigestSize(TPMI_ALG_HASH nameAlg) {
    return 0;
}

/**
 * @brief Defines a new Non-Volatile (NV) Index and reserves space for its data.
 * @param[in] auth Authorization token
 * @param[in] publicInfo A template for an area to create
 * @param[in] blameAuthHandle Return value if AuthHandle is invalid
 * @param[in] blameAuth Return value if Auth is invalid
 * @param[in] blamePublic Return value if publicInfo is invalid
 * @return Response code
 */
TPM_RC NvDefineSpace(
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
    if (authHandle == TPM_RH_PLATFORM && gc->phEnableNV == CLEAR)
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
    if (publicInfo->dataSize > S32K358_TPM_MAX_NV_BUFFER_SIZE
       && IS_ATTRIBUTE(attributes, TPMA_NV, WRITEALL))
        return TPM_RCS_SIZE + blamePublic;
    
    // And finally, see if the index is already defined.
    if (NvIndexIsDefined(publicInfo->nvIndex))
        return TPM_RC_NV_DEFINED;

    // Internal Data Update
    // define the space.  A TPM_RC_NV_SPACE error may be returned at this point
    return NvDefineIndex(publicInfo, auth);
}

/**
 * @brief Writes just the attributes of an index to NV.
 * @param[in] locator Location of the index.
 * @param[in] attributs Attributes to write to the index.
 * @return Response code
 */
static TPM_RC NvWriteNvIndexAttributes(NV_INDEX *nvIndex, TPMA_NV attributes)
{
    return NvWrite(locator + offsetof(NV_INDEX, publicArea.attributes),
                                sizeof(TPMA_NV),
                                &attributes) ? TPM_RC_SUCCESS : TPM_RC_FAILURE;
}

/**
 * @brief Writes data to the space reserved corresponding NvIndex.
 * @param[in] nvIndex The nvIndex of the space.
 * @param[in] offset The offset relative to the beginning of the start of the space.
 * @param[in] size The size of the buffer to be written to the space
 * @param[in] data A pointer to the buffer containing the data to be written to the space.
 * @return Response code
 */
TPM_RC
NvWriteIndexData(NV_INDEX* nvIndex,
                 UINT32    offset,
                 UINT32    size,
                 void*     data)
{
    TPM_RC result = TPM_RC_SUCCESS;

    assert(nvIndex != NULL);
    // Make sure that this is dealing with the 'default' index.
    // Note: it is tempting to change the calling sequence so that the 'default' is
    // presumed.
    //assert(nvIndex->publicArea.nvIndex == s_cachedNvIndex.publicArea.nvIndex);

    // Validate that write falls within range of the index
    assert(offset <= nvIndex->publicArea.dataSize
            && size <= (nvIndex->publicArea.dataSize - offset));

    // Update TPMA_NV_WRITTEN bit if necessary
    if(!IS_ATTRIBUTE(nvIndex->publicArea.attributes, TPMA_NV, WRITTEN))
    {
        // Update the in memory version of the attributes
        SET_ATTRIBUTE(nvIndex->publicArea.attributes, TPMA_NV, WRITTEN);

        // If this is not orderly, then update the NV version of
        // the attributes
        if (!IS_ATTRIBUTE(nvIndex->publicArea.attributes, TPMA_NV, ORDERLY)) {
            result = NvWriteNvIndexAttributes(s_cachedNvRef, nvIndex->publicArea.attributes);
            if (result != TPM_RC_SUCCESS)
                return result;
            // If this is a partial write of an ordinary index, clear the whole
            // index.
            //if(IsNvOrdinaryIndex(nvIndex->publicArea.attributes)
            //   && (nvIndex->publicArea.dataSize > size))
            //    _plat__NvMemoryClear(s_cachedNvRef + sizeof(NV_INDEX),
            //                         nvIndex->publicArea.dataSize);
        } else {
            //The orderly attribute was not implemented.
            return TPM_RC_ATTRIBUTES;
        }
    }
    if (IS_ATTRIBUTE(nvIndex->publicArea.attributes, TPMA_NV, ORDERLY)) {
        return TPM_RC_ATTRIBUTES;
    } else {
        result = NvConditionallyWrite(
            s_cachedNvRef + sizeof(NV_INDEX) + offset, size, data);
    }
    return result;
}

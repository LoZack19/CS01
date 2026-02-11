#include "hw/misc/s32k358_tpm.h"
#include "hw/misc/tpm_crypt.h"
#include "qemu/fifo8.h"
#include <string.h>
#include <stdlib.h>

/* Simplified key material used by the model to exercise crypto flows */
static const uint8_t DEFAULT_RSA_KEY[TPM_MAX_KEY_SIZE] = {0x11};
static const uint16_t DEFAULT_RSA_KEY_SIZE = 32; /* bytes */
static const uint8_t DEFAULT_AES_KEY[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
};
static const uint16_t DEFAULT_AES_KEY_SIZE = 16;
static TPM_HT HandleGetType(TPM_HANDLE handle) {
    return (TPM_HT)(handle >> HR_SHIFT);
}

/* TPM responses */

void tpm_finalize_response(S32k358TPMState *s)
{
    fifo8_reset(&s->infifo);

    s->tpm_state = TPM_S_CMPL;
    s->tpm_sts |= R_TPM_STS_dataAvail_MASK;
    s->tpm_sts |= R_TPM_STS_commandReady_MASK;
    s->tpm_sts &= ~R_TPM_STS_Expect_MASK;

    s->tpm_sts &= ~R_TPM_STS_burstCount_MASK;
    s->tpm_sts |= (fifo8_num_used(&s->outfifo)
                    << R_TPM_STS_burstCount_SHIFT)
                  & R_TPM_STS_burstCount_MASK;
}

void tpm_send_response(S32k358TPMState *s, TPM_RC rc, const void *data,
                       size_t size) {
    tpm_rsp_header_t rsp_header;

    rsp_header.tag = TPM_ST_NO_SESSIONS;
    rsp_header.responseCode = rc;

    if (rc == TPM_RC_SUCCESS && data != NULL && size > 0) {
        rsp_header.responseSize = sizeof(rsp_header) + size;
    } else {
        rsp_header.responseSize = sizeof(rsp_header);
    }

    MARSHAL(&s->outfifo, &rsp_header);

    if (rc == TPM_RC_SUCCESS && data != NULL && size > 0) {
        marshal(&s->outfifo, data, size);
    }

    qemu_log_mask(LOG_GUEST_ERROR,
                  "(INFO) TPM: Command completed, rc=0x%X, response size=%u\n",
                  rc, rsp_header.responseSize);

    tpm_finalize_response(s);
}

/* TPM Commands */

TPM_RC TPM2_GetRandom(GetRandom_In *in, GetRandom_Out *out) {
    // Truncate size to maximum supported digest size
    if (in->bytesRequested > sizeof(TPMU_HA)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "TPM2_GetRandom: Requested size %u exceeds maximum %zu, "
                      "truncating\n",
                      in->bytesRequested, sizeof(TPMU_HA));

        out->randomBytes.size = sizeof(TPMU_HA);
    } else {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "TPM2_GetRandom: Requested size %u is within limits, "
                      "generating random bytes\n",
                      in->bytesRequested);

        out->randomBytes.size = in->bytesRequested;
    }

    // Generate random bytes
    CryptRandomGenerate((uint16_t)out->randomBytes.size,
                        (uint8_t *)out->randomBytes.buffer);

    return TPM_RC_SUCCESS;
}

TPM_RC TPM2_NV_DefineSpace(NV_DefineSpace_In *in) {
    // This command only supports TPM_HT_NV_INDEX-typed NV indices.
    if (HandleGetType(in->publicInfo.nvPublic.nvIndex) != TPM_HT_NV_INDEX) {
        return TPM_RCS_HANDLE + RC_NV_DefineSpace_publicInfo;
    }

    return NvDefineSpace(in->authHandle, &in->auth, &in->publicInfo.nvPublic,
                         RC_NV_DefineSpace_authHandle, RC_NV_DefineSpace_auth,
                         RC_NV_DefineSpace_publicInfo);
}

TPM_RC TPM2_NV_Write(NV_Write_In *in) {
    NV_INDEX *nvIndex = NvGetIndexInfo(in->nvIndex, NULL);

    // Check if the index exists
    if (nvIndex == NULL) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "TPM2_NV_Write: Index 0x%08X not found\n", in->nvIndex);
        return TPM_RC_HANDLE;
    }

    TPMA_NV attributes = nvIndex->publicArea.attributes;
    TPM_RC result;

    // Input Validation

    // Common access checks, NvWriteAccessCheck() may return
    // TPM_RC_NV_AUTHORIZATION or TPM_RC_NV_LOCKED
    result = NvWriteAccessChecks(in->authHandle, in->nvIndex, attributes);
    if (result != TPM_RC_SUCCESS)
        return result;

    // Bits index, extend index or counter index may not be updated by
    // TPM2_NV_Write
    if (IsNvCounterIndex(attributes) || IsNvBitsIndex(attributes) ||
        IsNvExtendIndex(attributes))
        return TPM_RC_ATTRIBUTES;

    // Make sure that the offset is not too large
    if (in->offset > nvIndex->publicArea.dataSize)
        return TPM_RC_VALUE;

    // Make sure that the selection is within the range of the Index
    if (in->data.size > (nvIndex->publicArea.dataSize - in->offset))
        return TPM_RC_NV_RANGE;

    // If this index requires a full sized write, make sure that input range is
    // full sized.
    // Note: if the requested size is the same as the Index data size, then
    // offset will have to be zero. Otherwise, the range check above would have
    // failed.
    if (IS_ATTRIBUTE(attributes, TPMA_NV, WRITEALL) &&
        in->data.size < nvIndex->publicArea.dataSize)
        return TPM_RC_NV_RANGE;

    // Internal Data Update

    // Perform the write.  This called routine will SET the TPMA_NV_WRITTEN
    // attribute if it has not already been SET. If NV isn't available, an error
    // will be returned.
    return NvWriteIndexData(nvIndex, in->offset, in->data.size,
                            in->data.buffer);
}

TPM_RC TPM2_NV_Read(NV_Read_In *in, NV_Read_Out *out) {
    NV_REF locator;
    NV_INDEX *nvIndex = NvGetIndexInfo(in->nvIndex, &locator);
    TPM_RC result;

    // Check if the index exists
    if (nvIndex == NULL) {
        qemu_log_mask(LOG_GUEST_ERROR, "TPM2_NV_Read: Index 0x%08X not found\n",
                      in->nvIndex);
        return TPM_RC_HANDLE;
    }

    // Input Validation
    // Common read access checks. NvReadAccessChecks() may return
    // TPM_RC_NV_AUTHORIZATION, TPM_RC_NV_LOCKED, or TPM_RC_NV_UNINITIALIZED
    result = NvReadAccessChecks(in->authHandle, in->nvIndex,
                                nvIndex->publicArea.attributes);
    if (result != TPM_RC_SUCCESS)
        return result;

    // Make sure the data will fit the return buffer
    if (in->size > MAX_NV_BUFFER_SIZE)
        return TPM_RC_VALUE;

    // Verify that the offset is not too large
    if (in->offset > nvIndex->publicArea.dataSize)
        return TPM_RC_VALUE;

    // Make sure that the selection is within the range of the Index
    if (in->size > (nvIndex->publicArea.dataSize - in->offset))
        return TPM_RC_NV_RANGE;

    // Command Output
    // Set the return size
    out->data.size = in->size;

    // Perform the read
    NvGetIndexData(nvIndex, locator, in->offset, in->size, out->data.buffer);

    return TPM_RC_SUCCESS;
}
/* Cryptographic Operations */

TPM_RC TPM2_Sign(Sign_In *in, Sign_Out *out) {
    qemu_log_mask(LOG_GUEST_ERROR,
                  "TPM2_Sign: Signing digest with key handle 0x%08X\n",
                  in->keyHandle);

    if (in->digest.size == 0 || in->digest.size > sizeof(in->digest.buffer)) {
        return TPM_RC_VALUE;
    }

    if (in->inScheme.hashAlg != TPM_ALG_NULL &&
        in->inScheme.hashAlg != TPM_ALG_SHA256) {
        return TPM_RC_HASH;
    }

    CryptSignRSA_PSS_SHA256((const uint8_t *)in->digest.buffer, in->digest.size,
                            DEFAULT_RSA_KEY, DEFAULT_RSA_KEY_SIZE,
                            (uint8_t *)out->signature.signature.buffer);

    out->signature.sigAlg = TPM_ALG_RSASSA;
    out->signature.hashAlg = TPM_ALG_SHA256;
    out->signature.signature.size = DEFAULT_RSA_KEY_SIZE;

    return TPM_RC_SUCCESS;
}

TPM_RC TPM2_VerifySignature(VerifySignature_In *in, VerifySignature_Out *out) {
    qemu_log_mask(
        LOG_GUEST_ERROR,
        "TPM2_VerifySignature: Verifying signature with key handle 0x%08X\n",
        in->keyHandle);

    if (in->digest.size == 0 || in->signature.signature.size == 0) {
        return TPM_RC_SIGNATURE;
    }

    uint8_t ok = CryptVerifySignatureRSA_PSS_SHA256(
        (const uint8_t *)in->digest.buffer, (uint16_t)in->digest.size,
        (const uint8_t *)in->signature.signature.buffer,
        (uint16_t)in->signature.signature.size, DEFAULT_RSA_KEY,
        DEFAULT_RSA_KEY_SIZE);

    if (!ok) {
        return TPM_RC_SIGNATURE;
    }

    out->validation.tag = TPM_ST_NO_SESSIONS;
    out->validation.hierarchy = TPM_RH_OWNER;
    out->validation.digest = in->digest;

    return TPM_RC_SUCCESS;
}

TPM_RC TPM2_Hash(Hash_In *in, Hash_Out *out) {
    qemu_log_mask(LOG_GUEST_ERROR, "TPM2_Hash: Computing hash (alg=0x%04X)\n",
                  in->hashAlg);

    if (in->hashAlg != TPM_ALG_SHA256) {
        return TPM_RC_HASH;
    }

    if (in->data.size == 0) {
        return TPM_RC_HASH;
    }

    static int sha256_tested = 0;
    if (!sha256_tested) {
        test_sha256_implementation();
        sha256_tested = 1;
    }

    SHA256_Calculate((const uint8_t *)in->data.buffer,
                     (size_t)in->data.size,
                     (uint8_t *)out->digest.buffer);
    out->digest.size = SHA256_DIGEST_SIZE;

    out->validation.tag = TPM_ST_NO_SESSIONS;
    out->validation.hierarchy = in->hierarchy;
    out->validation.digest = out->digest;

    return TPM_RC_SUCCESS;
}

TPM_RC TPM2_EncryptDecrypt2(EncryptDecrypt2_In *in, EncryptDecrypt2_Out *out) {
    qemu_log_mask(LOG_GUEST_ERROR, "TPM2_EncryptDecrypt2: %s, Mode=0x%04X\n",
                  in->decrypt ? "Decrypt" : "Encrypt", in->mode);

    if (in->inData.size == 0) {
        return TPM_RC_VALUE;
    }

    if (in->mode != TPM_ALG_ECB && in->mode != TPM_ALG_CBC &&
        in->mode != TPM_ALG_CFB && in->mode != TPM_ALG_OFB &&
        in->mode != TPM_ALG_CTR) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "TPM2_EncryptDecrypt2: Unsupported mode 0x%04X\n",
                      in->mode);
        return TPM_RC_MODE;
    }

    if ((in->mode == TPM_ALG_ECB || in->mode == TPM_ALG_CBC) &&
        in->inData.size % 16 != 0) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "TPM2_EncryptDecrypt2: Data size %u not block-aligned "
                      "for mode 0x%04X\n",
                      in->inData.size, in->mode);
        return TPM_RC_VALUE;
    }

    if (in->mode != TPM_ALG_ECB && in->ivIn.size != 16) {
        qemu_log_mask(
            LOG_GUEST_ERROR,
            "TPM2_EncryptDecrypt2: Invalid IV size %u for mode 0x%04X\n",
            in->ivIn.size, in->mode);
        return TPM_RC_VALUE;
    }

    switch (in->mode) {
    case TPM_ALG_ECB: {
        if (in->decrypt) {
            TPM_AES_ECB_Decrypt(in->inData.buffer, in->inData.size,
                                DEFAULT_AES_KEY, DEFAULT_AES_KEY_SIZE,
                                out->outData.buffer);
        } else {
            TPM_AES_ECB_Encrypt(in->inData.buffer, in->inData.size,
                                DEFAULT_AES_KEY, DEFAULT_AES_KEY_SIZE,
                                out->outData.buffer);
        }
        out->outData.size = in->inData.size;
        out->ivOut.size = 0;
        break;
    }
    case TPM_ALG_CBC:
        if (in->decrypt) {
            TPM_AES_CBC_Decrypt(in->inData.buffer, in->inData.size,
                                DEFAULT_AES_KEY, DEFAULT_AES_KEY_SIZE,
                                in->ivIn.buffer, out->outData.buffer,
                                out->ivOut.buffer);
        } else {
            TPM_AES_CBC_Encrypt(in->inData.buffer, in->inData.size,
                                DEFAULT_AES_KEY, DEFAULT_AES_KEY_SIZE,
                                in->ivIn.buffer, out->outData.buffer,
                                out->ivOut.buffer);
        }
        out->outData.size = in->inData.size;
        out->ivOut.size = 16;
        break;
    case TPM_ALG_CFB:
        if (in->decrypt) {
            TPM_AES_CFB_Decrypt(in->inData.buffer, in->inData.size,
                                DEFAULT_AES_KEY, DEFAULT_AES_KEY_SIZE,
                                in->ivIn.buffer, out->outData.buffer,
                                out->ivOut.buffer);
        } else {
            TPM_AES_CFB_Encrypt(in->inData.buffer, in->inData.size,
                                DEFAULT_AES_KEY, DEFAULT_AES_KEY_SIZE,
                                in->ivIn.buffer, out->outData.buffer,
                                out->ivOut.buffer);
        }
        out->outData.size = in->inData.size;
        out->ivOut.size = 16;
        break;
    case TPM_ALG_OFB:
        TPM_AES_OFB_Process(in->inData.buffer, in->inData.size,
                            DEFAULT_AES_KEY, DEFAULT_AES_KEY_SIZE, in->ivIn.buffer,
                            out->outData.buffer, out->ivOut.buffer);
        out->outData.size = in->inData.size;
        out->ivOut.size = 16;
        break;
    case TPM_ALG_CTR:
        TPM_AES_CTR_Process(in->inData.buffer, in->inData.size,
                            DEFAULT_AES_KEY, DEFAULT_AES_KEY_SIZE, in->ivIn.buffer,
                            out->outData.buffer, out->ivOut.buffer);
        out->outData.size = in->inData.size;
        out->ivOut.size = 16;
        break;
    default:
        return TPM_RC_VALUE;
    }

    qemu_log_mask(LOG_GUEST_ERROR,
                  "TPM2_EncryptDecrypt2: Success, output size %u\n",
                  out->outData.size);

    return TPM_RC_SUCCESS;
}

TPM_RC TPM2_RSA_Encrypt(RSA_Encrypt_In *in, RSA_Encrypt_Out *out) {
    qemu_log_mask(LOG_GUEST_ERROR,
                  "TPM2_RSA_Encrypt: RSA encryption with handle 0x%08X\n",
                  in->keyHandle);

    if (in->message.size == 0 || in->message.size > TPM_MAX_KEY_SIZE) {
        return TPM_RC_VALUE;
    }

    TPM_RC crypt_rc = CryptEncrypt(in->message.buffer, in->message.size,
                                   DEFAULT_RSA_KEY, DEFAULT_RSA_KEY_SIZE,
                                   out->encrypted.buffer);
    if (crypt_rc != TPM_RC_SUCCESS) return crypt_rc;
    out->encrypted.size = in->message.size;

    return TPM_RC_SUCCESS;
}

TPM_RC TPM2_RSA_Decrypt(RSA_Decrypt_In *in, RSA_Decrypt_Out *out) {
    qemu_log_mask(LOG_GUEST_ERROR,
                  "TPM2_RSA_Decrypt: RSA decryption with handle 0x%08X\n",
                  in->keyHandle);

    if (in->encrypted.size == 0 || in->encrypted.size > TPM_MAX_KEY_SIZE) {
        return TPM_RC_VALUE;
    }

    TPM_RC crypt_rc = CryptDecrypt(in->encrypted.buffer, in->encrypted.size,
                                   DEFAULT_RSA_KEY, DEFAULT_RSA_KEY_SIZE,
                                   out->decrypted.buffer);
    if (crypt_rc != TPM_RC_SUCCESS) return crypt_rc;
    out->decrypted.size = in->encrypted.size;

    return TPM_RC_SUCCESS;
}

TPM_RC TPM2_CreatePrimary(CreatePrimary_In *in, CreatePrimary_Out *out) {
    TPM_RC result = TPM_RC_SUCCESS;
    TPMT_PUBLIC *publicArea;
    DRBG_STATE rand;
    OBJECT *newObject;
    TPM2B_NAME name;
    TPM2B_SEED primary_seed;
    TPM_HANDLE objectHandle;

    // Input Validation
    // Will need a place to put the result
    newObject = FindEmptyObjectSlot(&objectHandle);
    out->objectHandle = objectHandle;
    if (newObject == NULL)
        return TPM_RC_OBJECT_MEMORY;
    // Get the address of the public area in the new object
    // (this is just to save typing)
    publicArea = &newObject->publicArea;

    *publicArea = in->inPublic.publicArea;

    // Check attributes in input public area. CreateChecks() checks the things
    // that are unique to creation and then validates the attributes and values
    // that are common to create and load.
    result = CreateChecks(NULL, in->primaryHandle, publicArea,
                          in->inSensitive.sensitive.data.size);
    if (result != TPM_RC_SUCCESS)
        return RcSafeAddToResult(result, RC_CreatePrimary_inPublic);
    // Validate the sensitive area values
    if (!AdjustAuthSize(&in->inSensitive.sensitive.userAuth,
                        publicArea->nameAlg))
        return TPM_RCS_SIZE + RC_CreatePrimary_inSensitive;
    // Command output
    // Compute the name using out->name as a scratch area (this is not the value
    // that ultimately will be returned, then instantiate the state that will be
    // used as a random number generator during the object creation.
    // The caller does not know the seed values so the actual name does not have
    // to be over the input, it can be over the unmarshaled structure.

    result = HierarchyGetPrimarySeed(in->primaryHandle, &primary_seed);
    if (result != TPM_RC_SUCCESS)
        return result;

    result = DRBG_InstantiateSeeded(
        &rand, (const TPM2B *)&primary_seed, PRIMARY_OBJECT_CREATION,
        (const TPM2B *)PublicMarshalAndComputeName(publicArea, &name),
        (const TPM2B *)&in->inSensitive.sensitive.data);
    MemorySet(primary_seed.buffer, 0, primary_seed.size);

    if (result == TPM_RC_SUCCESS) {
        newObject->attributes.primary = SET;
        if (HierarchyNormalizeHandle(in->primaryHandle) == TPM_RH_ENDORSEMENT)
            newObject->attributes.epsHierarchy = SET;

        // Create the primary object.
        result = CryptCreateObject(newObject, &in->inSensitive.sensitive,
                                   (RAND_STATE *)&rand);
        DRBG_Uninstantiate(&rand);
    }
    if (result != TPM_RC_SUCCESS)
        return result;

    // Set the publicArea and name from the computed values
    out->outPublic.publicArea = newObject->publicArea;
    // Set size to actual marshaled size (not sizeof with padding)
    {
        BYTE marshalBuf[sizeof(TPMT_PUBLIC) * 2];
        out->outPublic.size = TPMT_PUBLIC_Marshal(&out->outPublic.publicArea,
                                                   marshalBuf);
    }
    out->name = newObject->name;

    // Fill in creation data
    FillInCreationData(in->primaryHandle, publicArea->nameAlg, &in->creationPCR,
                       &in->outsideInfo, &out->creationData,
                       &out->creationHash);

    // Compute creation ticket
    result =
        TicketComputeCreation(EntityGetHierarchy(in->primaryHandle), &out->name,
                              &out->creationHash, &out->creationTicket);
    if (result != TPM_RC_SUCCESS)
        return result;

    // Set the remaining attributes for a loaded object
    ObjectSetLoadedAttributes(newObject, in->primaryHandle);
    return result;
}

/*
 * TPM2_Create – Create an ordinary object under a parent key.
 *
 * Unlike CreatePrimary, Create uses the parent's protection seed and
 * returns a private blob (TPM2B_PRIVATE) + public area but does NOT
 * load the object into a transient slot.  The caller must use
 * TPM2_Load to make the object usable.
 *
 * Reference: ms-tpm-20-ref Create.c TPM2_Create()
 */
TPM_RC TPM2_Create(Create_In *in, Create_Out *out) {
    TPM_RC result = TPM_RC_SUCCESS;
    OBJECT *parentObject;
    OBJECT *newObject;
    TPMT_PUBLIC *publicArea;

    /* Input Validation */
    parentObject = HandleToObject(in->parentHandle);
    if (parentObject == NULL)
        return TPM_RCS_HANDLE + RC_Create_parentHandle;

    /* Does parent have the proper attributes? */
    if (!ObjectIsParent(parentObject))
        return TPM_RCS_TYPE + RC_Create_parentHandle;

    /* Get a temporary slot for the creation.
     * We use FindEmptyObjectSlot to get scratch space but we will
     * NOT leave the object loaded. */
    newObject = FindEmptyObjectSlot(NULL);
    if (newObject == NULL)
        return TPM_RC_OBJECT_MEMORY;

    publicArea = &newObject->publicArea;
    *publicArea = in->inPublic.publicArea;

    /* Check attributes. */
    result = CreateChecks(parentObject, 0, publicArea,
                          in->inSensitive.sensitive.data.size);
    if (result != TPM_RC_SUCCESS) {
        /* Free the slot before returning. */
        newObject->attributes.occupied = CLEAR;
        return RcSafeAddToResult(result, RC_Create_inPublic);
    }

    /* Validate the sensitive area values. */
    if (!AdjustAuthSize(&in->inSensitive.sensitive.userAuth,
                        publicArea->nameAlg)) {
        newObject->attributes.occupied = CLEAR;
        return TPM_RCS_SIZE + RC_Create_inSensitive;
    }

    /* Create the cryptographic material using the global RNG
     * (non-primary objects do not use a seeded DRBG). */
    result = CryptCreateObject(newObject, &in->inSensitive.sensitive, NULL);
    if (result != TPM_RC_SUCCESS) {
        newObject->attributes.occupied = CLEAR;
        return result;
    }

    /* Produce the output public area. */
    out->outPublic.publicArea = newObject->publicArea;
    /* Set size to actual marshaled size (not sizeof with padding). */
    {
        BYTE marshalBuf[sizeof(TPMT_PUBLIC) * 2];
        out->outPublic.size = TPMT_PUBLIC_Marshal(&out->outPublic.publicArea,
                                                   marshalBuf);
    }

    /* Wrap the sensitive area into the private blob.
     * Use a local to avoid passing a potentially unaligned pointer
     * from the packed Create_Out struct. */
    {
        TPM2B_PRIVATE tmpPrivate;
        SensitiveToPrivate(&newObject->sensitive, &newObject->name, parentObject,
                           newObject->publicArea.nameAlg, &tmpPrivate);
        out->outPrivate = tmpPrivate;
    }

    /* Fill in creation data. */
    FillInCreationData(in->parentHandle, publicArea->nameAlg, &in->creationPCR,
                       &in->outsideInfo, &out->creationData,
                       &out->creationHash);

    /* Compute creation ticket. */
    result = TicketComputeCreation(EntityGetHierarchy(in->parentHandle),
                                   &newObject->name, &out->creationHash,
                                   &out->creationTicket);

    /* Free the temporary slot – Create does NOT load the object. */
    newObject->attributes.occupied = CLEAR;

    return result;
}

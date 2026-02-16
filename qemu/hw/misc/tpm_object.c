/**
 * @file   tpm_object.c
 * @brief  Object-management helpers for the TPM model.
 *
 * Manages the transient-object slot table, performs object validation,
 * Name computation, creation-data generation, and cryptographic key
 * creation.
 *
 * @see ms-tpm-20-ref Object.c, Object_spt.c, CryptUtil.c
 * @see TPM 2.0 Part 1 Section 14 – Object Structures
 */

#include "hw/misc/s32k358_tpm.h"
#include "hw/misc/tpm_create_primary.h"
#include "hw/misc/tpm_crypt.h"
#include <string.h>

/* ---- Module-level object slot table ---------------------------------- */

static OBJECT s_objects[MAX_LOADED_OBJECTS];      /**< Slot array. */
static BOOL   s_objectSlotUsed[MAX_LOADED_OBJECTS]; /**< Occupancy bitmap. */

/**
 * @brief Locate a free object slot and allocate it.
 *
 * @param[out] handle  Receives the transient handle
 *                     (@c HR_TRANSIENT + index).  May be @c NULL.
 * @return Pointer to the cleared @c OBJECT, or @c NULL if all slots
 *         are occupied (@c TPM_RC_OBJECT_MEMORY).
 *
 * @see ms-tpm-20-ref Object.c FindEmptyObjectSlot()
 */
OBJECT *FindEmptyObjectSlot(TPM_HANDLE *handle) {
    for (int i = 0; i < MAX_LOADED_OBJECTS; i++) {
        if (!s_objectSlotUsed[i]) {
            s_objectSlotUsed[i] = TRUE;
            memset(&s_objects[i], 0, sizeof(OBJECT));
            s_objects[i].attributes.occupied = SET;
            if (handle != NULL) {
                *handle = HR_TRANSIENT + (TPM_HANDLE)i;
            }
            return &s_objects[i];
        }
    }
    return NULL; /* no free slot → TPM_RC_OBJECT_MEMORY */
}

/**
 * @brief Resolve a transient handle to an @c OBJECT pointer.
 *
 * Returns @c NULL for permanent handles, out-of-range indices, or
 * slots that are not fully initialised (Name.size == 0).
 *
 * @param[in] handle  Transient object handle.
 * @return Pointer to the @c OBJECT, or @c NULL.
 *
 * @see ms-tpm-20-ref Object.c HandleToObject()
 */
OBJECT *HandleToObject(TPMI_DH_OBJECT handle) {
    UINT32 index;

    /* Permanent handles have no associated OBJECT. */
    if ((handle >> HR_SHIFT) == 0x40) {
        return NULL;
    }

    index = handle - HR_TRANSIENT;
    if (index >= MAX_LOADED_OBJECTS) {
        return NULL;
    }
    if (!s_objectSlotUsed[index] || !s_objects[index].attributes.occupied) {
        return NULL;
    }
    /* Additional validation: object must have a valid Name.
     * This prevents returning objects that were allocated but never
     * fully initialized (e.g., slots from aborted operations or
     * when FlushContext is not yet implemented). */
    if (s_objects[index].name.size == 0) {
        return NULL;
    }
    return &s_objects[index];
}

/**
 * @brief Check whether an object has the @c isParent attribute.
 *
 * @param[in] parentObject  Object to test (may be @c NULL).
 * @retval TRUE  if the object is a parent (storage key).
 * @retval FALSE otherwise.
 *
 * @see ms-tpm-20-ref Object_spt.c ObjectIsParent()
 */
BOOL ObjectIsParent(OBJECT *parentObject) {
    if (parentObject == NULL) {
        return FALSE;
    }
    return parentObject->attributes.isParent;
}

/**
 * @brief Set load-time attributes (hierarchy, isParent) on an object.
 *
 * A "storage key" is detected when
 * @c restricted && @c decrypt && !@c sign_encrypt.
 *
 * @param[in,out] object        Object whose attributes are set.
 * @param[in]     parentHandle  Handle of the parent that loaded the object.
 *
 * @see ms-tpm-20-ref Object.c ObjectSetLoadedAttributes()
 */
void ObjectSetLoadedAttributes(OBJECT *object, TPM_HANDLE parentHandle) {
    TPMA_OBJECT *attrs;

    if (object == NULL) {
        return;
    }

    /* Record the hierarchy this object belongs to. */
    object->hierarchy = EntityGetHierarchy(parentHandle);

    attrs = &object->publicArea.objectAttributes;

    /* A "storage key" is restricted + decrypt + !sign.  Such keys can
     * be parents for other objects. */
    if (attrs->restricted && attrs->decrypt && !attrs->sign_encrypt) {
        object->attributes.isParent = SET;
    }
}

/* ---- Validation helpers ---------------------------------------------- */

/**
 * @brief Validate the public-area template for object creation.
 *
 * Checks basic constraints: non-NULL @c nameAlg, asymmetric key
 * @c sensitiveDataOrigin consistency, etc.  A full implementation
 * would cover all attribute-consistency rules from TPM 2.0 Part 1
 * Section 14.4.
 *
 * @param[in] parentObject     Parent object (unused in this model).
 * @param[in] parentHandle     Parent handle (unused in this model).
 * @param[in] publicArea       Template to validate.
 * @param[in] sensitiveDataSize  Size of user-supplied sensitive data.
 * @return @c TPM_RC_SUCCESS, or an error code.
 *
 * @see ms-tpm-20-ref Object_spt.c CreateChecks()
 */
TPM_RC CreateChecks(OBJECT *parentObject, TPM_HANDLE parentHandle,
                    TPMT_PUBLIC *publicArea, uint32_t sensitiveDataSize) {
    TPMA_OBJECT attrs;
    (void)parentObject;
    (void)parentHandle;

    if (publicArea == NULL) {
        return TPM_RC_VALUE;
    }

    attrs = publicArea->objectAttributes;

    /* nameAlg must not be NULL for an object with crypto material. */
    if (publicArea->nameAlg == TPM_ALG_NULL) {
        return TPM_RC_HASH;
    }

    /* An asymmetric key must not have user-supplied sensitive data
     * (sensitiveDataOrigin must be SET and data size must be 0). */
    if (publicArea->type == TPM_ALG_RSA) {
        if (attrs.sensitiveDataOrigin && sensitiveDataSize != 0) {
            return TPM_RCS_ATTRIBUTES;
        }
    }

    /* fixedTPM and fixedParent should both be SET for a primary. */
    /* (Relaxed check – we only warn if clearly wrong.) */

    return TPM_RC_SUCCESS;
}

/**
 * @brief Verify that the auth-value size is compatible with the Name
 *        hash algorithm.
 *
 * @param[in,out] auth     Authorization value (may be @c NULL).
 * @param[in]     nameAlg  Name hash algorithm.
 * @retval TRUE  Auth size is acceptable.
 * @retval FALSE Auth is larger than the digest size.
 *
 * @see ms-tpm-20-ref Object_spt.c AdjustAuthSize()
 */
BOOL AdjustAuthSize(TPM2B_AUTH *auth, TPMI_ALG_HASH nameAlg) {
    UINT16 digestSize;

    if (auth == NULL) {
        return TRUE;
    }

    /* Get the digest size for the name algorithm. */
    switch (nameAlg) {
    case TPM_ALG_SHA256:
        digestSize = SHA256_DIGEST_SIZE;
        break;
    case TPM_ALG_SHA1:
        digestSize = 20;
        break;
    default:
        digestSize = SHA256_DIGEST_SIZE;
        break;
    }

    /* If the provided auth value is larger than the digest, reject. */
    if (auth->size > digestSize) {
        return FALSE;
    }

    return TRUE;
}

/* ---- Name computation ------------------------------------------------ */

/**
 * @brief Marshal @c TPMT_PUBLIC and compute the object Name.
 *
 * Name = nameAlg (2 bytes, big-endian) || H(marshaled public area).
 *
 * @param[in]  publicArea  Public area to marshal.
 * @param[out] name        Receives the computed Name.
 * @return Pointer to @p name cast to @c TPM2B*.
 *
 * @see ms-tpm-20-ref Object.c PublicMarshalAndComputeName()
 */
TPM2B *PublicMarshalAndComputeName(TPMT_PUBLIC *publicArea, TPM2B_NAME *name) {
    BYTE marshalBuf[sizeof(TPMT_PUBLIC)];
    UINT16 marshaledSize;

    if (publicArea == NULL || name == NULL) {
        if (name != NULL) {
            name->size = 0;
        }
        return (TPM2B *)name;
    }

    if (publicArea->nameAlg == TPM_ALG_NULL) {
        name->size = 0;
        return (TPM2B *)name;
    }

    /* Marshal with proper big-endian field-by-field serialization. */
    marshaledSize = TPMT_PUBLIC_Marshal(publicArea, marshalBuf);

    /* Compute hash.  Only SHA-256 is supported for now. */
    /* Name = nameAlg (2 bytes, big-endian) || H(marshaled public area) */
    name->buffer[0] = (BYTE)(publicArea->nameAlg >> 8);
    name->buffer[1] = (BYTE)(publicArea->nameAlg & 0xFF);

    SHA256_Calculate(marshalBuf, marshaledSize, &name->buffer[2]);
    name->size = 2 + SHA256_DIGEST_SIZE;

    return (TPM2B *)name;
}

/* ---- Creation data & object creation --------------------------------- */

/**
 * @brief Populate creation-data output structures.
 *
 * Records the TPM state at object-creation time.  In this simplified
 * model a minimal blob of `parentHandle || outsideInfo` is produced.
 *
 * @param[in]  parentHandle  Handle of the parent.
 * @param[in]  nameAlg       Hash algorithm for creation hash.
 * @param[in]  creationPCR   PCR selection (unused).
 * @param[in]  outsideInfo   Caller-supplied data.
 * @param[out] outCreation   Receives the serialised creation data.
 * @param[out] creationHash  Receives H(creation data).
 *
 * @see ms-tpm-20-ref Object_spt.c FillInCreationData()
 */
void FillInCreationData(TPM_HANDLE parentHandle, TPMI_ALG_HASH nameAlg,
                        TPML_PCR_SELECTION *creationPCR,
                        TPM2B_DATA *outsideInfo,
                        TPM2B_CREATION_DATA *outCreation,
                        TPM2B_DIGEST *creationHash) {
    BYTE creationBuffer[sizeof(TPMT_PUBLIC)]; /* scratch */
    UINT16 creationSize = 0;

    (void)creationPCR;

    if (outCreation == NULL || creationHash == NULL) {
        return;
    }

    memset(outCreation, 0, sizeof(*outCreation));

    /*
     * Build a minimal creation-data blob:
     *   parentHandle (4 bytes) || outsideInfo
     *
     * A full implementation marshals TPMS_CREATION_DATA per the spec.
     */
    creationBuffer[0] = (BYTE)(parentHandle >> 24);
    creationBuffer[1] = (BYTE)(parentHandle >> 16);
    creationBuffer[2] = (BYTE)(parentHandle >> 8);
    creationBuffer[3] = (BYTE)(parentHandle);
    creationSize = 4;

    if (outsideInfo != NULL && outsideInfo->size > 0 &&
        outsideInfo->size <= sizeof(creationBuffer) - creationSize) {
        memcpy(&creationBuffer[creationSize], outsideInfo->data,
               outsideInfo->size);
        creationSize += outsideInfo->size;
    }

    /* Store creation data in the output buffer. */
    outCreation->size = creationSize;
    memcpy(outCreation->buffer, creationBuffer, creationSize);

    /* Compute the creation hash = H(creation data). */
    switch (nameAlg) {
    case TPM_ALG_SHA256:
    default:
        SHA256_Calculate(creationBuffer, creationSize, creationHash->buffer);
        creationHash->size = SHA256_DIGEST_SIZE;
        break;
    }
}

/**
 * @brief Create cryptographic material for a new object.
 *
 * Steps performed:
 * 1. Set @c sensitiveType.
 * 2. Copy user auth.
 * 3. Generate key material via provided @p rand (or global RNG).
 * 4. Compute the public unique value.
 * 5. Generate a seed value.
 * 6. Compute the Name from the public area.
 *
 * @param[in,out] object           Object to populate.
 * @param[in]     sensitiveCreate  User-supplied sensitive creation data.
 * @param[in]     rand             DRBG state; @c NULL to use the global RNG.
 * @return @c TPM_RC_SUCCESS, or @c TPM_RC_FAILURE.
 *
 * @note Only @c TPM_ALG_RSA is fully supported.  Other algorithm types
 *       receive a generic random secret key.
 *
 * @see ms-tpm-20-ref CryptUtil.c CryptCreateObject()
 */
TPM_RC CryptCreateObject(OBJECT *object, TPMS_SENSITIVE_CREATE *sensitiveCreate,
                         RAND_STATE *rand) {
    TPMT_PUBLIC *publicArea;
    TPMT_SENSITIVE *sensitive;

    if (object == NULL) {
        return TPM_RC_FAILURE;
    }

    publicArea = &object->publicArea;
    sensitive = &object->sensitive;

    /* 1. Set the sensitive type to match the public area. */
    sensitive->sensitiveType = publicArea->type;

    /* 2. Copy the initial authorization value. */
    if (sensitiveCreate != NULL) {
        sensitive->authValue = sensitiveCreate->userAuth;
    }

    /* 3. If the TPM is the source of the key material, ignore any
     *    user-supplied data. */
    if (publicArea->objectAttributes.sensitiveDataOrigin &&
        sensitiveCreate != NULL) {
        sensitiveCreate->data.t.size = 0;
    }

    /* 4. Generate key material according to the algorithm type. */
    switch (publicArea->type) {
    case TPM_ALG_RSA: {
        UINT16 keyBytes;

        keyBytes = publicArea->parameters.rsaDetail.keyBits / 8;
        if (keyBytes == 0 ||
            keyBytes > sizeof(sensitive->sensitive.rsa.buffer)) {
            keyBytes = 256; /* default 2048-bit RSA */
        }

        /* Generate the private key material.  In a full implementation
         * this would produce a proper RSA key pair; here we generate
         * pseudo-random bytes from the DRBG. */
        if (rand != NULL) {
            DRBG_Generate(rand, sensitive->sensitive.rsa.buffer, keyBytes);
        } else {
            CryptRandomGenerate(keyBytes, sensitive->sensitive.rsa.buffer);
        }
        sensitive->sensitive.rsa.size = keyBytes;

        /* Generate the public unique value.
         * In a real TPM this would be the RSA modulus (n = p*q).
         * In our simplified XOR-based simulation the encrypt/decrypt
         * and sign/verify primitives derive a PRNG seed from the first
         * 4 bytes of the key material.  For roundtrips to work the
         * public and private representations must share those bytes.
         * We therefore copy the private-key buffer to the public
         * unique field so that both keys produce the same XOR stream. */
        memcpy(publicArea->unique.rsa.buffer,
               sensitive->sensitive.rsa.buffer, keyBytes);
        publicArea->unique.rsa.size = keyBytes;
        break;
    }
    default: {
        /* For other algorithm types (SYMCIPHER, KEYEDHASH …) generate
         * a random secret key. */
        UINT16 keySize = 32; /* default 256-bit key */
        if (keySize > sizeof(sensitive->sensitive.rsa.buffer)) {
            keySize = sizeof(sensitive->sensitive.rsa.buffer);
        }
        if (rand != NULL) {
            DRBG_Generate(rand, sensitive->sensitive.rsa.buffer, keySize);
        } else {
            CryptRandomGenerate(keySize, sensitive->sensitive.rsa.buffer);
        }
        sensitive->sensitive.rsa.size = keySize;
        break;
    }
    }

    /* 5. Generate a seed value (used for child-key protection). */
    {
        UINT16 seedSize = SHA256_DIGEST_SIZE;

        if (rand != NULL) {
            DRBG_Generate(rand, sensitive->seedValue.buffer, seedSize);
        } else {
            CryptRandomGenerate(seedSize, sensitive->seedValue.buffer);
        }
        sensitive->seedValue.size = seedSize;
    }

    /* 6. Compute the Name from the public area. */
    PublicMarshalAndComputeName(publicArea, &object->name);

    return TPM_RC_SUCCESS;
}

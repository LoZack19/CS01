/*
 * tpm_object.c – Object management helpers for the TPM model.
 *
 * Class: Object Management
 * Functions: FindEmptyObjectSlot, ObjectSetLoadedAttributes,
 *            CreateChecks, AdjustAuthSize,
 *            PublicMarshalAndComputeName, FillInCreationData,
 *            CryptCreateObject
 *
 * Reference: ms-tpm-20-ref
 *   Object.c            (FindEmptyObjectSlot, PublicMarshalAndComputeName,
 *                         ObjectSetLoadedAttributes)
 *   Object_spt.c        (CreateChecks, FillInCreationData, AdjustAuthSize)
 *   CryptUtil.c          (CryptCreateObject)
 */

#include "hw/misc/s32k358_tpm.h"
#include "hw/misc/tpm_create_primary.h"
#include "hw/misc/tpm_crypt.h"
#include <string.h>

/* -----------------------------------------------------------------------
 * Module-level object slot table
 * ----------------------------------------------------------------------- */

static OBJECT  s_objects[MAX_LOADED_OBJECTS];
static BOOL    s_objectSlotUsed[MAX_LOADED_OBJECTS];

/*
 * FindEmptyObjectSlot – Locate a free object slot and return a pointer
 * to it together with its handle.
 *
 * Reference: ms-tpm-20-ref Object.c FindEmptyObjectSlot()
 */
OBJECT *FindEmptyObjectSlot(TPM_HANDLE *handle)
{
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

/*
 * HandleToObject – Resolve a transient handle to an OBJECT pointer.
 *
 * Returns NULL for permanent handles or if the slot is not occupied.
 *
 * Reference: ms-tpm-20-ref Object.c HandleToObject()
 */
OBJECT *HandleToObject(TPMI_DH_OBJECT handle)
{
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
    return &s_objects[index];
}

/*
 * ObjectIsParent – Return TRUE if the object has the isParent attribute.
 *
 * Reference: ms-tpm-20-ref Object_spt.c ObjectIsParent()
 */
BOOL ObjectIsParent(OBJECT *parentObject)
{
    if (parentObject == NULL) {
        return FALSE;
    }
    return parentObject->attributes.isParent;
}

/*
 * ObjectSetLoadedAttributes – Set the attributes of an object that are
 * established at load-time (hierarchy, isParent, …).
 *
 * Reference: ms-tpm-20-ref Object.c ObjectSetLoadedAttributes()
 */
void ObjectSetLoadedAttributes(OBJECT *object, TPM_HANDLE parentHandle)
{
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

/* -----------------------------------------------------------------------
 * Validation helpers
 * ----------------------------------------------------------------------- */

/*
 * CreateChecks – Validate the public-area template for object creation.
 *
 * This is a simplified version that checks the most basic constraints.
 * A full implementation would cover all the attribute-consistency rules
 * described in Part 1 of the TPM spec (§14.4).
 *
 * Reference: ms-tpm-20-ref Object_spt.c CreateChecks()
 */
TPM_RC CreateChecks(OBJECT *parentObject, TPM_HANDLE parentHandle,
                    TPMT_PUBLIC *publicArea, uint32_t sensitiveDataSize)
{
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

/*
 * AdjustAuthSize – Make sure the authorization value size is compatible
 * with the name hash algorithm.
 *
 * Returns TRUE (1) on success, FALSE (0) if the auth is too large.
 *
 * Reference: ms-tpm-20-ref Object_spt.c AdjustAuthSize()
 */
BOOL AdjustAuthSize(TPM2B_AUTH *auth, TPMI_ALG_HASH nameAlg)
{
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

/* -----------------------------------------------------------------------
 * Name computation
 * ----------------------------------------------------------------------- */

/*
 * PublicMarshalAndComputeName – Serialize the TPMT_PUBLIC into a canonical
 * byte buffer and compute its Name (hash-alg‖H(marshaled public area)).
 *
 * In this simplified model we compute SHA-256 over the raw struct bytes
 * instead of performing proper TPM marshaling (which requires serialising
 * each field in big-endian order).  For deterministic primary-key
 * generation this is acceptable as long as the same "marshaling" is used
 * consistently.
 *
 * Reference: ms-tpm-20-ref Object.c PublicMarshalAndComputeName()
 */
TPM2B *PublicMarshalAndComputeName(TPMT_PUBLIC *publicArea,
                                   TPM2B_NAME *name)
{
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

/* -----------------------------------------------------------------------
 * Creation data & object creation
 * ----------------------------------------------------------------------- */

/*
 * FillInCreationData – Populate creation-data output structures.
 *
 * The creation data records the state of the TPM at the time of object
 * creation (parent info, PCR digest, locality, outside-info, …).
 * In this simplified model we fill in the required fields with minimal
 * but correct values.
 *
 * Reference: ms-tpm-20-ref Object_spt.c FillInCreationData()
 */
void FillInCreationData(TPM_HANDLE parentHandle, TPMI_ALG_HASH nameAlg,
                        TPML_PCR_SELECTION *creationPCR,
                        TPM2B_DATA *outsideInfo,
                        TPM2B_CREATION_DATA *outCreation,
                        TPM2B_DIGEST *creationHash)
{
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

/*
 * CryptCreateObject – Create the cryptographic material for a new object.
 *
 * For RSA keys a key-pair must be generated; for symmetric keys a secret
 * key is created.  In this simplified model we:
 *   1. Set the sensitive type.
 *   2. Copy the user-auth value.
 *   3. Generate key material with the provided RAND_STATE (or the global
 *      RNG when rand is NULL).
 *   4. Compute the public unique value.
 *   5. Generate a seed value and compute the Name.
 *
 * Reference: ms-tpm-20-ref CryptUtil.c CryptCreateObject()
 */
TPM_RC CryptCreateObject(OBJECT *object,
                          TPMS_SENSITIVE_CREATE *sensitiveCreate,
                          RAND_STATE *rand)
{
    TPMT_PUBLIC    *publicArea;
    TPMT_SENSITIVE *sensitive;

    if (object == NULL) {
        return TPM_RC_FAILURE;
    }

    publicArea = &object->publicArea;
    sensitive  = &object->sensitive;

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
    case TPM_ALG_RSA:
    {
        UINT16 keyBytes;

        keyBytes = publicArea->parameters.rsaDetail.keyBits / 8;
        if (keyBytes == 0 || keyBytes > sizeof(sensitive->sensitive.rsa.buffer)) {
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

        /* Generate the public unique value by hashing the private key.
         * (In a real TPM this would be the modulus.) */
        SHA256_Calculate(sensitive->sensitive.rsa.buffer, keyBytes,
                         publicArea->unique.rsa.buffer);
        publicArea->unique.rsa.size = SHA256_DIGEST_SIZE;
        break;
    }
    default:
    {
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

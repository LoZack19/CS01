/**
 * @file tpm_load.c
 * @brief TPM2_Load command and private-blob wrapping (Spec Part 3, Section 5.4).
 *
 * Provides functions to wrap and unwrap @c TPMT_SENSITIVE into a
 * @c TPM2B_PRIVATE blob, validate and install non-primary objects,
 * and implement the TPM2_Load command handler.
 *
 *   - @ref PrivateToSensitive  — unwrap a TPM2B_PRIVATE blob.
 *   - @ref SensitiveToPrivate  — wrap a TPMT_SENSITIVE into a blob.
 *   - @ref ObjectLoad          — validate and install a loaded object.
 *   - @ref TPM2_Load           — TPM2_Load command handler.
 *
 * @see tpm_object.c  for object-slot management.
 * @see ms-tpm-20-ref Object_spt.c, Object.c, Load.c
 */

#include "hw/misc/s32k358_tpm.h"
#include "hw/misc/tpm_create_primary.h"
#include "hw/misc/tpm_crypt.h"
#include <string.h>

/* ---- Private blob handling ------------------------------------------- */

/**
 * @brief Unwrap a @c TPM2B_PRIVATE blob into @c TPMT_SENSITIVE.
 *
 * In a full TPM this involves HMAC integrity checking and symmetric
 * decryption.  In this simplified model the blob is a raw copy of
 * @c TPMT_SENSITIVE followed by a SHA-256 integrity digest.  The
 * integrity digest binds the private blob to the public area (via
 * the Name) so that tampering is detected at load time.
 *
 * @param[in]  inPrivate  Wrapped private blob.
 * @param[in]  name       Object Name (used for integrity check).
 * @param[in]  parent     Parent object (unused in simplified model).
 * @param[in]  nameAlg    Name hash algorithm (unused in simplified model).
 * @param[out] sensitive  Recovered TPMT_SENSITIVE on success.
 * @return TPM_RC_SUCCESS, TPM_RCS_SIZE, or TPM_RCS_BINDING.
 *
 * @see ms-tpm-20-ref Object_spt.c PrivateToSensitive()
 */
TPM_RC PrivateToSensitive(TPM2B *inPrivate, TPM2B *name,
                          OBJECT *parent, TPM_ALG_ID nameAlg,
                          TPMT_SENSITIVE *sensitive)
{
    (void)parent;
    (void)nameAlg;

    if (inPrivate == NULL || sensitive == NULL) {
        return TPM_RC_FAILURE;
    }

    if (inPrivate->size == 0) {
        return TPM_RCS_SIZE;
    }

    UINT16 expectedSize = (UINT16)(sizeof(TPMT_SENSITIVE) + SHA256_DIGEST_SIZE);

    /* The simplified private blob layout is:
     *   [TPMT_SENSITIVE bytes][SHA256 integrity digest (32 bytes)]
     * Verify the blob has the expected size. */
    if (inPrivate->size < expectedSize) {
        return TPM_RCS_SIZE;
    }

    /* Extract the TPMT_SENSITIVE. */
    memcpy(sensitive, inPrivate->buffer, sizeof(TPMT_SENSITIVE));

    /* Verify the integrity digest: SHA256(Name || sensitive).
     * This detects any tampering with the public area (which changes
     * the Name) since the stored digest was computed at creation time. */
    BYTE integrityInput[sizeof(TPM2B_NAME) + sizeof(TPMT_SENSITIVE)];
    UINT16 inputSize = 0;

    if (name != NULL && name->size > 0) {
        memcpy(integrityInput, name->buffer, name->size);
        inputSize = name->size;
    }
    memcpy(integrityInput + inputSize, sensitive, sizeof(TPMT_SENSITIVE));
    inputSize += (UINT16)sizeof(TPMT_SENSITIVE);

    BYTE computedIntegrity[SHA256_DIGEST_SIZE];
    SHA256_Calculate(integrityInput, inputSize, computedIntegrity);

    const BYTE *storedIntegrity =
        inPrivate->buffer + sizeof(TPMT_SENSITIVE);
    if (memcmp(storedIntegrity, computedIntegrity, SHA256_DIGEST_SIZE) != 0) {
        return TPM_RCS_BINDING;
    }

    return TPM_RC_SUCCESS;
}

/**
 * @brief Wrap a @c TPMT_SENSITIVE into a @c TPM2B_PRIVATE blob.
 *
 * Stores the raw sensitive bytes followed by a SHA-256 integrity
 * digest computed over @c Name || sensitive.  This binds the private
 * blob to the public area so that tampering with either is detected
 * at load time.
 *
 * @param[in]  sensitive   Sensitive area to wrap.
 * @param[in]  name        Object Name (included in integrity hash).
 * @param[in]  parent      Parent object (unused in simplified model).
 * @param[in]  nameAlg     Name hash algorithm (unused).
 * @param[out] outPrivate  Output private blob.
 *
 * @see ms-tpm-20-ref Object_spt.c SensitiveToPrivate()
 */
void SensitiveToPrivate(TPMT_SENSITIVE *sensitive, TPM2B_NAME *name,
                        OBJECT *parent, TPM_ALG_ID nameAlg,
                        TPM2B_PRIVATE *outPrivate)
{
    (void)parent;
    (void)nameAlg;

    if (sensitive == NULL || outPrivate == NULL) {
        if (outPrivate != NULL) {
            outPrivate->size = 0;
        }
        return;
    }

    UINT16 copySize = (UINT16)sizeof(TPMT_SENSITIVE);
    if (copySize > sizeof(outPrivate->buffer) - SHA256_DIGEST_SIZE) {
        copySize = sizeof(outPrivate->buffer) - SHA256_DIGEST_SIZE;
    }

    /* Store the raw TPMT_SENSITIVE. */
    memcpy(outPrivate->buffer, sensitive, copySize);

    /* Compute and append an integrity digest: SHA256(Name || sensitive).
     * This binds the private blob to the public area (via the Name)
     * so that tampering with the public area is detected at load time. */
    BYTE integrityInput[sizeof(TPM2B_NAME) + sizeof(TPMT_SENSITIVE)];
    UINT16 inputSize = 0;

    if (name != NULL && name->size > 0) {
        memcpy(integrityInput, name->buffer, name->size);
        inputSize = name->size;
    }
    memcpy(integrityInput + inputSize, sensitive, copySize);
    inputSize += copySize;

    SHA256_Calculate(integrityInput, inputSize,
                     outPrivate->buffer + copySize);
    outPrivate->size = copySize + SHA256_DIGEST_SIZE;
}

/**
 * @brief Validate and install a non-primary object into a slot.
 *
 * Copies the public and sensitive areas into the object, performs
 * attribute-consistency checks, computes the Name, and marks the
 * slot as occupied.
 *
 * @param[in,out] object       Target object slot.
 * @param[in]     parent       Parent object (unused in simplified model).
 * @param[in]     publicArea   Public template.
 * @param[in]     sensitive    Sensitive area (may be @c NULL for public-only).
 * @param[in]     blamePublic  RC modifier for public-area errors.
 * @param[in]     blameSensitive RC modifier for sensitive-area errors.
 * @param[out]    name         Computed object Name (if not @c NULL).
 * @return TPM_RC_SUCCESS or validation error.
 *
 * @see ms-tpm-20-ref Object.c ObjectLoad()
 */
TPM_RC ObjectLoad(OBJECT *object, OBJECT *parent,
                  TPMT_PUBLIC *publicArea, TPMT_SENSITIVE *sensitive,
                  TPM_RC blamePublic, TPM_RC blameSensitive,
                  TPM2B_NAME *name)
{
    (void)parent;

    if (object == NULL || publicArea == NULL) {
        return TPM_RC_FAILURE;
    }

    /* 1. Install the public area. */
    object->publicArea = *publicArea;

    /* 1b. Attribute consistency: for RSA (and other asymmetric types),
     *     at least one of sign_encrypt or decrypt must be SET. */
    if (publicArea->type == TPM_ALG_RSA &&
        !publicArea->objectAttributes.sign_encrypt &&
        !publicArea->objectAttributes.decrypt) {
        return TPM_RC_ATTRIBUTES + blamePublic;
    }

    /* 2. Install the sensitive area if provided. */
    if (sensitive != NULL) {
        object->sensitive = *sensitive;

        /* Basic binding check: the sensitive type must match the
         * public area algorithm. */
        if (sensitive->sensitiveType != publicArea->type) {
            return TPM_RCS_BINDING + blameSensitive;
        }

        /* Key-size consistency: for RSA, the private key material size
         * must match the declared keyBits in the public area. */
        if (publicArea->type == TPM_ALG_RSA) {
            UINT16 expectedBytes =
                publicArea->parameters.rsaDetail.keyBits / 8;
            if (expectedBytes > 0 &&
                sensitive->sensitive.rsa.size != expectedBytes) {
                return TPM_RC_KEY_SIZE + blamePublic;
            }
        }
    }

    /* 3. Compute the Name.  If the nameAlg is NULL the object has no
     *    name (public-only external object). */
    if (publicArea->nameAlg != TPM_ALG_NULL) {
        PublicMarshalAndComputeName(publicArea, &object->name);
        if (object->name.size == 0) {
            return TPM_RCS_HASH + blamePublic;
        }
    } else {
        object->name.size = 0;
    }

    /* 4. Copy the name to the output parameter (if provided). */
    if (name != NULL) {
        *name = object->name;
    }

    /* 5. Compute a simplified qualified name.
     *    QN = H_nameAlg(QN_parent || Name)
     *    For simplicity, QN = Name for now. */
    object->qualifiedName = object->name;

    /* 6. Mark the slot as occupied. */
    object->attributes.occupied = SET;

    return TPM_RC_SUCCESS;
}

/**
 * @brief Load a child object into a transient slot (Spec Part 3, Section 5.4).
 *
 * Allocates a slot, unwraps the private blob via
 * @ref PrivateToSensitive, validates the object via
 * @ref ObjectLoad, and sets loaded attributes.
 *
 * @param[in]  in   Parent handle, public area, and private blob.
 * @param[out] out  Assigned transient handle and computed Name.
 * @return TPM_RC_SUCCESS or load-specific error.
 *
 * @see ms-tpm-20-ref Load.c TPM2_Load()
 */
TPM_RC TPM2_Load(Load_In *in, Load_Out *out)
{
    TPM_RC         result = TPM_RC_SUCCESS;
    TPMT_SENSITIVE sensitive;
    OBJECT        *parentObject;
    OBJECT        *newObject;

    /* Input Validation */

    /* Don't get invested in loading if there is no place to put it. */
    /* Use local variable to avoid taking address of packed member. */
    TPM_HANDLE objectHandle;
    newObject = FindEmptyObjectSlot(&objectHandle);
    if (newObject == NULL)
        return TPM_RC_OBJECT_MEMORY;
    out->objectHandle = objectHandle;

    if (in->inPrivate.size == 0)
        return TPM_RCS_SIZE + RC_Load_inPrivate;

    parentObject = HandleToObject(in->parentHandle);
    if (parentObject == NULL)
        return TPM_RCS_HANDLE + RC_Load_parentHandle;

    /* Is the object that is being used as the parent actually a parent. */
    if (!ObjectIsParent(parentObject))
        return TPM_RCS_TYPE + RC_Load_parentHandle;

    /* Compute the name of the object.  If there isn't one, it is because
     * the nameAlg is not valid. */
    PublicMarshalAndComputeName(&in->inPublic.publicArea, &out->name);
    if (out->name.size == 0)
        return TPM_RCS_HASH + RC_Load_inPublic;

    /* Retrieve the sensitive data from the private blob. */
    result = PrivateToSensitive((TPM2B *)&in->inPrivate.b,
                                (TPM2B *)&out->name,
                                parentObject,
                                in->inPublic.publicArea.nameAlg,
                                &sensitive);
    if (result != TPM_RC_SUCCESS)
        return RcSafeAddToResult(result, RC_Load_inPrivate);

    /* Internal Data Update – load and validate object. */
    result = ObjectLoad(newObject,
                        parentObject,
                        &in->inPublic.publicArea,
                        &sensitive,
                        RC_Load_inPublic,
                        RC_Load_inPrivate,
                        &out->name);
    if (result == TPM_RC_SUCCESS) {
        /* Set the common OBJECT attributes for a loaded object. */
        ObjectSetLoadedAttributes(newObject, in->parentHandle);
    }
    return result;
}

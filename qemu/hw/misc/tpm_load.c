/*
 * tpm_load.c – TPM2_Load command and support functions.
 *
 * Functions:
 *   PrivateToSensitive  – unwrap a TPM2B_PRIVATE blob into TPMT_SENSITIVE
 *   SensitiveToPrivate  – wrap a TPMT_SENSITIVE into a TPM2B_PRIVATE blob
 *   ObjectLoad          – validate and install a non-primary object
 *   TPM2_Load           – TPM2_Load command handler
 *
 * Reference: ms-tpm-20-ref
 *   Object_spt.c  (PrivateToSensitive, SensitiveToPrivate)
 *   Object.c      (ObjectLoad)
 *   Load.c        (TPM2_Load)
 */

#include "hw/misc/s32k358_tpm.h"
#include "hw/misc/tpm_create_primary.h"
#include "hw/misc/tpm_crypt.h"
#include <string.h>

/* -----------------------------------------------------------------------
 * PrivateToSensitive – Unwrap an input TPM2B_PRIVATE area.
 *
 * In a full TPM implementation this function:
 *   1. Checks the HMAC integrity of the private area.
 *   2. Decrypts the private buffer using the parent's symmetric key.
 *   3. Unmarshals the resulting TPMT_SENSITIVE.
 *
 * In this simplified model the private blob is just a raw copy of
 * TPMT_SENSITIVE (produced by SensitiveToPrivate), so we memcpy it
 * back.
 *
 * Reference: ms-tpm-20-ref Object_spt.c PrivateToSensitive()
 * ----------------------------------------------------------------------- */
TPM_RC PrivateToSensitive(TPM2B *inPrivate, TPM2B *name,
                          OBJECT *parent, TPM_ALG_ID nameAlg,
                          TPMT_SENSITIVE *sensitive)
{
    (void)name;
    (void)parent;
    (void)nameAlg;

    if (inPrivate == NULL || sensitive == NULL) {
        return TPM_RC_FAILURE;
    }

    if (inPrivate->size == 0) {
        return TPM_RCS_SIZE;
    }

    /* The simplified private blob contains a raw TPMT_SENSITIVE.
     * Verify the size is plausible. */
    if (inPrivate->size < sizeof(TPMT_SENSITIVE)) {
        /* The blob is too small – data was probably corrupted or
         * produced by a different (full) implementation. Fall back
         * to copying as much as we have. */
        memset(sensitive, 0, sizeof(*sensitive));
        memcpy(sensitive, inPrivate->buffer, inPrivate->size);
    } else {
        memcpy(sensitive, inPrivate->buffer, sizeof(TPMT_SENSITIVE));
    }

    return TPM_RC_SUCCESS;
}

/* -----------------------------------------------------------------------
 * SensitiveToPrivate – Wrap a TPMT_SENSITIVE into a TPM2B_PRIVATE blob.
 *
 * In the full spec this marshals + encrypts + HMACs the sensitive data.
 * In our simplified model we just copy the raw TPMT_SENSITIVE bytes.
 *
 * Reference: ms-tpm-20-ref Object_spt.c SensitiveToPrivate()
 * ----------------------------------------------------------------------- */
void SensitiveToPrivate(TPMT_SENSITIVE *sensitive, TPM2B_NAME *name,
                        OBJECT *parent, TPM_ALG_ID nameAlg,
                        TPM2B_PRIVATE *outPrivate)
{
    (void)name;
    (void)parent;
    (void)nameAlg;

    if (sensitive == NULL || outPrivate == NULL) {
        if (outPrivate != NULL) {
            outPrivate->size = 0;
        }
        return;
    }

    UINT16 copySize = (UINT16)sizeof(TPMT_SENSITIVE);
    if (copySize > sizeof(outPrivate->buffer)) {
        copySize = sizeof(outPrivate->buffer);
    }

    memcpy(outPrivate->buffer, sensitive, copySize);
    outPrivate->size = copySize;
}

/* -----------------------------------------------------------------------
 * ObjectLoad – Common function to load a non-primary object.
 *
 * A loaded object has its public area validated (unless nameAlg is
 * TPM_ALG_NULL).  If a sensitive part is loaded, it is verified to
 * be correct and if both public and sensitive parts are loaded, then
 * the cryptographic binding between the objects is validated.
 *
 * In this simplified model we:
 *   1. Copy the public area into the object slot.
 *   2. Copy the sensitive area (if present).
 *   3. Compute the object Name from the public area.
 *   4. Mark the slot as in use.
 *
 * Reference: ms-tpm-20-ref Object.c ObjectLoad()
 * ----------------------------------------------------------------------- */
TPM_RC ObjectLoad(OBJECT *object, OBJECT *parent,
                  TPMT_PUBLIC *publicArea, TPMT_SENSITIVE *sensitive,
                  TPM_RC blamePublic, TPM_RC blameSensitive,
                  TPM2B_NAME *name)
{
    (void)blamePublic;
    (void)blameSensitive;

    if (object == NULL || publicArea == NULL) {
        return TPM_RC_FAILURE;
    }

    /* 1. Install the public area. */
    object->publicArea = *publicArea;

    /* 2. Install the sensitive area if provided. */
    if (sensitive != NULL) {
        object->sensitive = *sensitive;

        /* Basic binding check: the sensitive type must match the
         * public area algorithm. */
        if (sensitive->sensitiveType != publicArea->type) {
            return TPM_RCS_BINDING + blameSensitive;
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

/* -----------------------------------------------------------------------
 * TPM2_Load – Load an ordinary or temporary object.
 *
 * Reference: ms-tpm-20-ref Load.c TPM2_Load()
 * ----------------------------------------------------------------------- */
TPM_RC TPM2_Load(Load_In *in, Load_Out *out)
{
    TPM_RC         result = TPM_RC_SUCCESS;
    TPMT_SENSITIVE sensitive;
    OBJECT        *parentObject;
    OBJECT        *newObject;

    /* Input Validation */

    /* Don't get invested in loading if there is no place to put it. */
    newObject = FindEmptyObjectSlot(&out->objectHandle);
    if (newObject == NULL)
        return TPM_RC_OBJECT_MEMORY;

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

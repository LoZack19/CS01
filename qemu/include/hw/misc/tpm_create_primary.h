#ifndef HW_MISC_TPM_CREATE_PRIMARY_H
#define HW_MISC_TPM_CREATE_PRIMARY_H

/*
 * Declarations for all functions required by TPM2_CreatePrimary.
 *
 * These functions are organized by class:
 *   - Utility        (tpm_util.c)        : MemorySet, RcSafeAddToResult
 *   - Hierarchy      (tpm_hierarchy.c)   : HierarchyGetPrimarySeed,
 *                                          HierarchyNormalizeHandle,
 *                                          EntityGetHierarchy
 *   - Object Mgmt    (tpm_object.c)      : FindEmptyObjectSlot,
 *                                          ObjectSetLoadedAttributes,
 *                                          CreateChecks, AdjustAuthSize,
 *                                          PublicMarshalAndComputeName,
 *                                          FillInCreationData,
 *                                          CryptCreateObject
 *   - DRBG           (tpm_drbg.c)        : DRBG_InstantiateSeeded,
 *                                          DRBG_Uninstantiate, DRBG_Generate
 *   - Ticket         (tpm_ticket.c)      : TicketComputeCreation
 */

#include "hw/misc/tpm2_spec_protocol.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Forward declaration – avoids pulling in the full QEMU device header.
 * When s32k358_tpm.h has already been included, S32k358TPMState is
 * already fully defined. */
struct S32k358TPMState;

/* ========================================================================
 * Utility (tpm_util.c)
 * ======================================================================== */

void MemorySet(void *dest, int val, size_t size);

TPM_RC RcSafeAddToResult(TPM_RC result, TPM_RC modifier);

/* ========================================================================
 * Hierarchy (tpm_hierarchy.c)
 * ======================================================================== */

/*
 * Set the global TPM device-state pointer used by hierarchy functions.
 * Must be called once from the device realize callback (s32k358_tpm.c).
 */
void tpm_hierarchy_set_state(struct S32k358TPMState *s);

TPM_RC HierarchyGetPrimarySeed(TPM_HANDLE hierarchy, TPM2B_SEED *seed);

TPM_HANDLE HierarchyNormalizeHandle(TPM_HANDLE handle);

TPMI_RH_HIERARCHY EntityGetHierarchy(TPM_HANDLE handle);

/* ========================================================================
 * Object Management (tpm_object.c)
 * ======================================================================== */

/*
 * Maximum number of simultaneously loaded transient objects.
 * The ms-tpm-20-ref uses a similar compile-time constant.
 */
#define MAX_LOADED_OBJECTS 8

/* First transient handle (HR_TRANSIENT) */
#define HR_TRANSIENT 0x80000000

OBJECT *FindEmptyObjectSlot(TPM_HANDLE *handle);

void ObjectSetLoadedAttributes(OBJECT *object, TPM_HANDLE parentHandle);

TPM_RC CreateChecks(OBJECT *parentObject, TPM_HANDLE parentHandle,
                    TPMT_PUBLIC *publicArea, uint32_t sensitiveDataSize);

BOOL AdjustAuthSize(TPM2B_AUTH *auth, TPMI_ALG_HASH nameAlg);

TPM2B *PublicMarshalAndComputeName(TPMT_PUBLIC *publicArea,
                                   TPM2B_NAME *name);

void FillInCreationData(TPM_HANDLE parentHandle, TPMI_ALG_HASH nameAlg,
                        TPML_PCR_SELECTION *creationPCR,
                        TPM2B_DATA *outsideInfo,
                        TPM2B_CREATION_DATA *outCreation,
                        TPM2B_DIGEST *creationHash);

TPM_RC CryptCreateObject(OBJECT *object,
                          TPMS_SENSITIVE_CREATE *sensitiveCreate,
                          RAND_STATE *rand);

/* ========================================================================
 * DRBG (tpm_drbg.c)
 * ======================================================================== */

#define DRBG_MAGIC 0x47425244 /* "DRBG" little-endian */

TPM_RC DRBG_InstantiateSeeded(DRBG_STATE *drbgState, const TPM2B *seed,
                              const char *purpose, const TPM2B *name,
                              const TPM2B *additional);

TPM_RC DRBG_Uninstantiate(DRBG_STATE *drbgState);

UINT16 DRBG_Generate(RAND_STATE *state, BYTE *random, UINT16 randomSize);

/* ========================================================================
 * Ticket (tpm_ticket.c)
 * ======================================================================== */

TPM_RC TicketComputeCreation(TPMI_RH_HIERARCHY hierarchy, TPM2B_NAME *name,
                             TPM2B_DIGEST *creation,
                             TPMT_TK_CREATION *ticket);

/* ========================================================================
 * Object – Load support (tpm_object.c + tpm_load.c)
 * ======================================================================== */

/*
 * HandleToObject – Resolve a transient handle to an OBJECT pointer.
 * Returns NULL for permanent handles or if the slot is not occupied.
 *
 * Reference: ms-tpm-20-ref Object.c HandleToObject()
 */
OBJECT *HandleToObject(TPMI_DH_OBJECT handle);

/*
 * ObjectIsParent – Return TRUE if the object has the isParent attribute set.
 *
 * Reference: ms-tpm-20-ref Object_spt.c ObjectIsParent()
 */
BOOL ObjectIsParent(OBJECT *parentObject);

/*
 * PrivateToSensitive – Unwrap a TPM2B_PRIVATE blob into a TPMT_SENSITIVE.
 *
 * In the full spec this involves HMAC integrity check and decryption.
 * Our simplified model just copies the marshaled TPMT_SENSITIVE out of
 * the blob.
 *
 * Reference: ms-tpm-20-ref Object_spt.c PrivateToSensitive()
 */
TPM_RC PrivateToSensitive(TPM2B *inPrivate, TPM2B *name,
                          OBJECT *parent, TPM_ALG_ID nameAlg,
                          TPMT_SENSITIVE *sensitive);

/*
 * SensitiveToPrivate – Wrap a TPMT_SENSITIVE into a TPM2B_PRIVATE blob.
 *
 * Simplified model: copies the raw TPMT_SENSITIVE bytes into the private
 * buffer.
 *
 * Reference: ms-tpm-20-ref Object_spt.c SensitiveToPrivate()
 */
void SensitiveToPrivate(TPMT_SENSITIVE *sensitive, TPM2B_NAME *name,
                        OBJECT *parent, TPM_ALG_ID nameAlg,
                        TPM2B_PRIVATE *outPrivate);

/*
 * ObjectLoad – Common function to load a non-primary object.
 * Validates the public area, loads sensitive if present, and
 * checks cryptographic binding.
 *
 * Reference: ms-tpm-20-ref Object.c ObjectLoad()
 */
TPM_RC ObjectLoad(OBJECT *object, OBJECT *parent,
                  TPMT_PUBLIC *publicArea, TPMT_SENSITIVE *sensitive,
                  TPM_RC blamePublic, TPM_RC blameSensitive,
                  TPM2B_NAME *name);

#endif /* HW_MISC_TPM_CREATE_PRIMARY_H */

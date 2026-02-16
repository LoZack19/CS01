#ifndef HW_MISC_TPM_CREATE_PRIMARY_H
#define HW_MISC_TPM_CREATE_PRIMARY_H

/**
 * @file   tpm_create_primary.h
 * @brief  Umbrella header for all functions required by TPM2_CreatePrimary.
 *
 * Declarations are organized by functional class:
 *
 * | Class         | Source file        | Functions                          |
 * |---------------|--------------------|---------------------------------|
 * | Utility       | tpm_util.c         | MemorySet, RcSafeAddToResult       |
 * | Hierarchy     | tpm_hierarchy.c    | HierarchyGetPrimarySeed, …         |
 * | Object Mgmt   | tpm_object.c       | FindEmptyObjectSlot, …             |
 * | TPM Marshal   | tpm_marshal_tpm.c  | TPMT_PUBLIC_Marshal                |
 * | DRBG          | tpm_drbg.c         | DRBG_InstantiateSeeded, …          |
 * | Ticket        | tpm_ticket.c       | TicketComputeCreation              |
 */

#include "hw/misc/tpm2_spec_protocol.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * @brief Forward declaration of the QEMU device state.
 *
 * Avoids pulling in the full device header; when
 * [s32k358_tpm.h](include/hw/misc/s32k358_tpm.h) is already included,
 * @c S32k358TPMState is fully defined.
 */
struct S32k358TPMState;

/* ---- Utility (tpm_util.c) -------------------------------------------- */

/** @brief Wrapper around @c memset with a @c NULL guard. */
void MemorySet(void *dest, int val, size_t size);

/** @brief Combine a base return code with a parameter/handle modifier. */
TPM_RC RcSafeAddToResult(TPM_RC result, TPM_RC modifier);

/* ---- Hierarchy (tpm_hierarchy.c) ------------------------------------- */

/**
 * @brief Register the device state for hierarchy seed look-ups.
 *
 * Must be called exactly once from the device @c realize callback.
 */
void tpm_hierarchy_set_state(struct S32k358TPMState *s);

/** @brief Return the primary seed for a given hierarchy handle. */
TPM_RC HierarchyGetPrimarySeed(TPM_HANDLE hierarchy, TPM2B_SEED *seed);

/** @brief Map FW-/SVN-limited hierarchy handles to their base. */
TPM_HANDLE HierarchyNormalizeHandle(TPM_HANDLE handle);

/** @brief Determine the hierarchy to which @p handle belongs. */
TPMI_RH_HIERARCHY EntityGetHierarchy(TPM_HANDLE handle);

/* ---- Object Management (tpm_object.c) -------------------------------- */

#define MAX_LOADED_OBJECTS 16   /**< Max simultaneous transient objects. */
#define HR_TRANSIENT 0x80000000 /**< First transient handle. */

/** @brief Allocate a free object slot and return a transient handle. */
OBJECT *FindEmptyObjectSlot(TPM_HANDLE *handle);

/** @brief Set load-time attributes (hierarchy, isParent). */
void ObjectSetLoadedAttributes(OBJECT *object, TPM_HANDLE parentHandle);

/** @brief Validate public-area template for object creation. */
TPM_RC CreateChecks(OBJECT *parentObject, TPM_HANDLE parentHandle,
                    TPMT_PUBLIC *publicArea, uint32_t sensitiveDataSize);

/** @brief Verify auth-value size against the Name algorithm. */
BOOL AdjustAuthSize(TPM2B_AUTH *auth, TPMI_ALG_HASH nameAlg);

/** @brief Marshal @c TPMT_PUBLIC and compute the object Name. */
TPM2B *PublicMarshalAndComputeName(TPMT_PUBLIC *publicArea,
                                   TPM2B_NAME *name);

/**
 * @brief Marshal @c TPMT_PUBLIC into canonical big-endian wire format.
 *
 * Used for Name computation and @c outPublic sizing.
 *
 * @param[in]  publicArea  Public area to marshal.
 * @param[out] buffer      Destination buffer.
 * @return Actual marshaled size in bytes.
 *
 * @see TPM 2.0 Part 2 – Table 184 (TPMT_PUBLIC definition)
 */
UINT16 TPMT_PUBLIC_Marshal(const TPMT_PUBLIC *publicArea, BYTE *buffer);

/** @brief Populate creation-data output structures (minimal). */
void FillInCreationData(TPM_HANDLE parentHandle, TPMI_ALG_HASH nameAlg,
                        TPML_PCR_SELECTION *creationPCR,
                        TPM2B_DATA *outsideInfo,
                        TPM2B_CREATION_DATA *outCreation,
                        TPM2B_DIGEST *creationHash);

/** @brief Create cryptographic material for a new object. */
TPM_RC CryptCreateObject(OBJECT *object,
                          TPMS_SENSITIVE_CREATE *sensitiveCreate,
                          RAND_STATE *rand);

/* ---- DRBG (tpm_drbg.c) ----------------------------------------------- */

#define DRBG_MAGIC 0x47425244 /**< "DRBG" in little-endian. */

/** @brief Derive a DRBG state from a primary seed and context data. */
TPM_RC DRBG_InstantiateSeeded(DRBG_STATE *drbgState, const TPM2B *seed,
                              const char *purpose, const TPM2B *name,
                              const TPM2B *additional);

/** @brief Securely zeroize the DRBG state. */
TPM_RC DRBG_Uninstantiate(DRBG_STATE *drbgState);

/** @brief Produce pseudo-random bytes from the DRBG state. */
UINT16 DRBG_Generate(RAND_STATE *state, BYTE *random, UINT16 randomSize);

/* ---- Ticket (tpm_ticket.c) ------------------------------------------- */

/** @brief Compute a @c TPMT_TK_CREATION for a newly created primary. */
TPM_RC TicketComputeCreation(TPMI_RH_HIERARCHY hierarchy, TPM2B_NAME *name,
                             TPM2B_DIGEST *creation,
                             TPMT_TK_CREATION *ticket);

/* ---- Object – Load support (tpm_object.c + tpm_load.c) --------------- */

/** @brief Resolve a transient handle to an @c OBJECT pointer. */
OBJECT *HandleToObject(TPMI_DH_OBJECT handle);

/** @brief Check whether the object has the @c isParent attribute set. */
BOOL ObjectIsParent(OBJECT *parentObject);

/**
 * @brief Unwrap a @c TPM2B_PRIVATE blob into a @c TPMT_SENSITIVE.
 *
 * Simplified model: copies the marshaled @c TPMT_SENSITIVE directly
 * without HMAC integrity check.
 *
 * @see ms-tpm-20-ref Object_spt.c PrivateToSensitive()
 */
TPM_RC PrivateToSensitive(TPM2B *inPrivate, TPM2B *name,
                          OBJECT *parent, TPM_ALG_ID nameAlg,
                          TPMT_SENSITIVE *sensitive);

/**
 * @brief Wrap a @c TPMT_SENSITIVE into a @c TPM2B_PRIVATE blob.
 *
 * Simplified model: copies the raw @c TPMT_SENSITIVE bytes.
 *
 * @see ms-tpm-20-ref Object_spt.c SensitiveToPrivate()
 */
void SensitiveToPrivate(TPMT_SENSITIVE *sensitive, TPM2B_NAME *name,
                        OBJECT *parent, TPM_ALG_ID nameAlg,
                        TPM2B_PRIVATE *outPrivate);

/**
 * @brief Load a non-primary object, validate public area and
 *        cryptographic binding.
 *
 * @see ms-tpm-20-ref Object.c ObjectLoad()
 */
TPM_RC ObjectLoad(OBJECT *object, OBJECT *parent,
                  TPMT_PUBLIC *publicArea, TPMT_SENSITIVE *sensitive,
                  TPM_RC blamePublic, TPM_RC blameSensitive,
                  TPM2B_NAME *name);

/* ---- Authorization (tpm_auth.c) -------------------------------------- */

/** @brief Forward declaration to avoid including qemu/fifo8.h. */
struct Fifo8;

/**
 * @brief Parse authorization area from the command FIFO.
 *
 * For @c TPM_ST_SESSIONS commands, parses the authorization area that
 * follows the command parameters.  Supports password authorization
 * (@c TPM_RS_PW) with empty passwords.
 *
 * @param[in]  fifo     Command FIFO.
 * @param[out] authCmd  Parsed authorization command on success.
 * @return @c TPM_RC_SUCCESS on success, or an appropriate error code.
 */
TPM_RC ParseAuthArea(Fifo8 *fifo, TPMS_AUTH_COMMAND *authCmd);

/**
 * @brief Marshal authorization response area to the output FIFO.
 *
 * Marshals an empty nonce and HMAC for password-session responses.
 *
 * @param[in,out] fifo  Output FIFO.
 */
void MarshalAuthResponse(Fifo8 *fifo);

#endif /* HW_MISC_TPM_CREATE_PRIMARY_H */

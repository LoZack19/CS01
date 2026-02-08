/*
 * tpm_support.c – TPM support stubs.
 *
 * The functions that were previously stubbed here have been moved to
 * dedicated implementation files organized by class:
 *
 *   tpm_util.c       – MemorySet, RcSafeAddToResult
 *   tpm_hierarchy.c  – HierarchyGetPrimarySeed, HierarchyNormalizeHandle,
 *                      EntityGetHierarchy
 *   tpm_object.c     – FindEmptyObjectSlot, ObjectSetLoadedAttributes,
 *                      CreateChecks, AdjustAuthSize,
 *                      PublicMarshalAndComputeName, FillInCreationData,
 *                      CryptCreateObject
 *   tpm_drbg.c       – DRBG_InstantiateSeeded, DRBG_Uninstantiate,
 *                      DRBG_Generate
 *   tpm_ticket.c     – TicketComputeCreation
 *
 * This file is kept in the build for any future generic support helpers.
 */

#include "hw/misc/s32k358_tpm.h"
#include "hw/misc/tpm_crypt.h"
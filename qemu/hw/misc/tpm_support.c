/**
 * @file   tpm_support.c
 * @brief  TPM support stubs (placeholder).
 *
 * Functions that were previously stubbed here have been moved to
 * dedicated implementation files organized by class:
 *
 * | File             | Functions                                        |
 * |------------------|--------------------------------------------------|
 * | tpm_util.c       | MemorySet, RcSafeAddToResult                     |
 * | tpm_hierarchy.c  | HierarchyGetPrimarySeed, HierarchyNormalizeHandle|
 * | tpm_object.c     | FindEmptyObjectSlot, CryptCreateObject, …        |
 * | tpm_drbg.c       | DRBG_InstantiateSeeded, DRBG_Generate, …         |
 * | tpm_ticket.c     | TicketComputeCreation                            |
 *
 * This file is kept in the build for any future generic support helpers.
 */

#include "hw/misc/s32k358_tpm.h"
#include "hw/misc/tpm_crypt.h"
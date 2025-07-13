#ifndef HW_MISC_S32K358_TPM_H
#define HW_MISC_S32K358_TPM_H

#include "qemu/osdep.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "hw/sysbus.h"
#include "migration/vmstate.h"
#include "hw/irq.h"
#include "qom/object.h"
#include "qemu/log.h"

#include "hw/registerfields.h"
#include "include/qemu/fifo8.h"

#define TYPE_S32K358_TPM                  "s32k358_tpm"
OBJECT_DECLARE_SIMPLE_TYPE(S32k358TPMState, S32K358_TPM)

#define S32K358_TPM_MEM_SIZE 0x10

#define S32K358_TPM_INFIFO_SIZE 1024
#define S32K358_TPM_OUTFIFO_SIZE 1024

#define STATUS_RST 0x00
#define CONTROL_RST 0x00
#define DATA_RST 0x00

struct S32k358TPMState {
    SysBusDevice parent_obj;

    MemoryRegion iomem;

    uint8_t tpm_access;
    uint32_t tpm_int_enable;
    uint8_t tpm_int_vector;
    uint32_t tpm_int_status;
    uint32_t tpm_intf_caps;
    uint32_t tpm_sts;
    uint32_t tpm_data;
    uint32_t tpm_interface_id;
    uint32_t tpm_xdata_fifo;
    uint32_t tpm_did_vid;
    uint8_t tpm_rid;

    Fifo8 infifo;
    Fifo8 outfifo;
};

REG8(TPM_ACCESS,        0x0000)  // Access Control Register
    FIELD(TPM_ACCESS, requestUse, 1, 1)
    FIELD(TPM_ACCESS, activeLocality, 5, 1)
REG32(TPM_INT_ENABLE,   0x0008)  // Interrupt Enable Register
REG8(TPM_INT_VECTOR,    0x000C)  // Interrupt Vector Register
REG32(TPM_INT_STATUS,   0x0010)  // Interrupt Status Register
REG32(TPM_INTF_CAPS,    0x0014)  // Interface Capabilities Register
REG32(TPM_STS,          0x0018)  // Status Register
REG32(TPM_DATA,         0x0024)  // Data Register (ReadFIFO / WriteFIFO depending on direction)
REG32(TPM_INTERFACE_ID, 0x0030)  // Interface ID Register
REG32(TPM_XDATA_FIFO,   0x0080)  // Extended Data FIFO Register (ReadFIFO / WriteFIFO depending on direction)
REG32(TPM_DID_VID,      0x0F00)  // Device ID and Vendor ID Register
REG8(TPM_RID,           0x0F04)  // Revision ID Register

#endif

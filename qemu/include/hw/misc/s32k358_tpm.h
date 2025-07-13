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

    uint8_t status;
    uint8_t control;
    uint8_t data;

    Fifo8 infifo;
    Fifo8 outfifo;
};

REG32(STATUS,  0x000)
    FIELD(STATUS, DAV, 0, 1) // Data Available
    FIELD(STATUS, FULL, 1, 1) // Input FIFO Full
REG32(CONTROL, 0x001)
    FIELD(STATUS, IDAV, 0, 1) // Interrupt on Data Available
REG32(DATA,    0x002)

#endif

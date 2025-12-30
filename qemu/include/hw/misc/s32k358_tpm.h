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
#include "hw/misc/tpm2_spec_protocol.h"

#define TYPE_S32K358_TPM                  "s32k358_tpm"
OBJECT_DECLARE_SIMPLE_TYPE(S32k358TPMState, S32K358_TPM)

#define S32K358_TPM_MEM_SIZE 0x4000

#define S32K358_TPM_INFIFO_SIZE 4096
#define S32K358_TPM_OUTFIFO_SIZE 4096

#define TPM_STATE_RST TPM_S_INIT

#define TPM_ACCESS_RST          0x00
#define TPM_INT_ENABLE_RST      0x00000000
#define TPM_INT_VECTOR_RST      0x00
#define TPM_INT_STATUS_RST      0x00000000
#define TPM_INTF_CAPS_RST       0x00000000
#define TPM_STS_RST             0x00000000
    #define TPM_STS_burstCount_RST      64
#define TPM_DATA_FIFO_RST       0x00000000
#define TPM_INTERFACE_ID_RST    0x00000000
#define TPM_XDATA_FIFO_RST      0x00000000
#define TPM_DID_VID_RST         0x00000000
#define TPM_RID_RST             0x00

// NV Memory Configuration
#define S32K358_TPM_NV_MEM_SIZE 1024
#define S32K358_TPM_MAX_NV_BUFFER_SIZE 1024
#define S32K358_TPM_NV_MEM_FIRST_VALID_ADDR 0x04

// Response functions
void tpm_send_response(S32k358TPMState *s, TPM_RC rc,
                       const void *data, size_t size);

static inline
void tpm_send_error_response(S32k358TPMState *s, TPM_RC rc) {
    tpm_send_response(s, rc, NULL, 0);
}

struct S32k358TPMState {
    SysBusDevice parent_obj;

    MemoryRegion iomem;

    enum {
        TPM_S_INIT,
        TPM_S_IDLE,
        TPM_S_READY,
        TPM_S_RECV,
        TPM_S_EXEC,
        TPM_S_CMPL
    } tpm_state;

    uint8_t tpm_access;
    uint32_t tpm_int_enable;
    uint8_t tpm_int_vector;
    uint32_t tpm_int_status;
    uint32_t tpm_intf_caps;
    uint32_t tpm_sts;
    uint32_t tpm_data_fifo;
    uint32_t tpm_interface_id;
    uint32_t tpm_xdata_fifo;
    uint32_t tpm_did_vid;
    uint8_t tpm_rid;

    // Fields for the NV index implementation
    uint8_t mem[S32K358_TPM_NV_MEM_SIZE];
    uint32_t nvmem_size;
    char *filename;

    state_clear_data gc;

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
    FIELD(TPM_STS, Expect, 3, 1) // Data can be sent to TPM
    FIELD(TPM_STS, dataAvail, 4, 1) // Data can be received from TPM
    FIELD(TPM_STS, tpmGo, 5, 1) // Start command execution
    FIELD(TPM_STS, commandReady, 6, 1) // Start receiving
    FIELD(TPM_STS, burstCount, 8, 16) // Data that can be sent/received without waiting
REG32(TPM_DATA_FIFO,    0x0024)  // Data Register (ReadFIFO / WriteFIFO depending on direction)
REG32(TPM_INTERFACE_ID, 0x0030)  // Interface ID Register
REG32(TPM_XDATA_FIFO,   0x0080)  // Extended Data FIFO Register (ReadFIFO / WriteFIFO depending on direction)
REG32(TPM_DID_VID,      0x0F00)  // Device ID and Vendor ID Register
REG8(TPM_RID,           0x0F04)  // Revision ID Register

#endif

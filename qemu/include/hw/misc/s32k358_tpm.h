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

#define __packed __attribute__((packed))

#define TYPE_S32K358_TPM                  "s32k358_tpm"
OBJECT_DECLARE_SIMPLE_TYPE(S32k358TPMState, S32K358_TPM)

#define S32K358_TPM_MEM_SIZE 0x4000

#define S32K358_TPM_INFIFO_SIZE 1024
#define S32K358_TPM_OUTFIFO_SIZE 1024

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
    FIELD(TPM_STS, burstCount, 8, 16)
    FIELD(TPM_STS, commandReady, 6, 1) // Start receiving
    FIELD(TPM_STS, tpmGo, 5, 1) // Start command execution
    FIELD(TPM_STS, dataAvail, 4, 1)
REG32(TPM_DATA_FIFO,    0x0024)  // Data Register (ReadFIFO / WriteFIFO depending on direction)
REG32(TPM_INTERFACE_ID, 0x0030)  // Interface ID Register
REG32(TPM_XDATA_FIFO,   0x0080)  // Extended Data FIFO Register (ReadFIFO / WriteFIFO depending on direction)
REG32(TPM_DID_VID,      0x0F00)  // Device ID and Vendor ID Register
REG8(TPM_RID,           0x0F04)  // Revision ID Register

/* TPM specific types */

// Constants

#define TPM_NT_ORDINARY 0x0
#define TPM_NT_COUNTER 0x1
#define TPM_NT_BITS 0x2
#define TPM_NT_EXTEND 0x4
#define TPM_NT_PIN_FAIL 0x8
#define TPM_NT_PIN_PASS 0x9

// Basic definitions

typedef uint32_t TPM_CC;
#define TPM_CC_GetRandom 0x0000017B
#define TPM_CC_NV_DefineSpace 0x0000012A

// Response Codes
typedef uint32_t TPM_RC;
#define TPM_RC_SUCCESS      (TPM_RC)0x000
#define TPM_RC_H            (TPM_RC)(0x000)  /* Error due to handle */
#define TPM_RC_P            (TPM_RC)(0x040)  /* Error due to parameter */
#define TPM_RC_(n)          (TPM_RC)((n) << 8)
#define TPM_RC_1            (TPM_RC)(TPM_RC_(1))  /* first (modifier) */
#define TPM_RC_2            (TPM_RC)(TPM_RC_(2))  /* second (modifier) */
#define TPM_RC_3            (TPM_RC)(TPM_RC_(3))  /* third (modifier) */
#define TPM_RC_BAD_TAG      (TPM_RC)0x01E
#define RC_VER1             (TPM_RC)0x100
#define TPM_RC_COMMAND_SIZE (TPM_RC)(RC_VER1 + 0x42)
#define TPM_RC_COMMAND_CODE (TPM_RC)(RC_VER1 + 0x43)
#define TPM_RC_NV_DEFINED   (TPM_RC)(RC_VER1 + 0x4C)
#define RC_FMT1             (TPM_RC)(0x080)
#define TPM_RC_ATTRIBUTES   (TPM_RC)(RC_FMT1 + 0x002)
#define TPM_RCS_ATTRIBUTES  (TPM_RC)(RC_FMT1 + 0x002)
#define TPM_RC_HIERARCHY    (TPM_RC)(RC_FMT1 + 0x005)
#define TPM_RCS_HIERARCHY   (TPM_RC)(RC_FMT1 + 0x005)
#define TPM_RC_HANDLE       (TPM_RC)(RC_FMT1 + 0x00B)
#define TPM_RCS_HANDLE      (TPM_RC)(RC_FMT1 + 0x00B)
#define TPM_RCS_SIZE        (TPM_RC)(RC_FMT1 + 0x015)


// Response Code Modifiers
#define RC_NV_DefineSpace_authHandle (TPM_RC_H + TPM_RC_1)
#define RC_NV_DefineSpace_auth       (TPM_RC_P + TPM_RC_1)
#define RC_NV_DefineSpace_publicInfo (TPM_RC_P + TPM_RC_2)

typedef uint16_t TPM_ST;
typedef uint16_t TPMI_ST_COMMAND_TAG;
#define TPM_ST_NO_SESSIONS 0x8001
#define TPM_ST_SESSIONS    0x8002

typedef uint8_t BOOL;
typedef uint8_t BYTE;
typedef uint8_t UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;

typedef UINT8 TPM_HT;

typedef UINT16 TPM_ALG_ID;

typedef UINT32 TPM_HANDLE;

// Restriction of basic types
#define TPM_RH_OWNER 0x40000001
#define TPM_RH_PLATFORM 0x4000000C
typedef TPM_HANDLE TPMI_RH_PROVISION;

#define TPM_HT_NV_INDEX 0x01
#define HR_SHIFT 24
#define HR_NV_INDEX (TPM_HT_NV_INDEX << HR_SHIFT)
#define NV_INDEX_FIRST (HR_NV_INDEX + 0)
#define NV_INDEX_LAST (NV_INDEX_FIRST + 0x00FFFFFF)
typedef TPM_HANDLE TPMI_RH_NV_LEGACY_INDEX;

/* #define TPM_ALG_!ALG.H */
#define TPM_ALG_NULL 0x0010
typedef TPM_ALG_ID TPMI_ALG_HASH;

// Access to bitfields
#define IS_ATTRIBUTE(a, type, b)    ((a.b) != 0)
#define SET_ATTRIBUTE(a, type, b)   (a.b = SET)
#define CLEAR_ATTRIBUTE(a, type, b) (a.b = CLEAR)
#define GET_ATTRIBUTE(a, type, b)   (a.b)

// Structured types
#define SHA256_DIGEST_SIZE 32

typedef union __packed {
    BYTE sha256[SHA256_DIGEST_SIZE];
} TPMU_HA;

typedef struct __packed {
    UINT16 size;
    BYTE buffer[sizeof(TPMU_HA)];
} TPM2B_DIGEST;

#define MAX_NV_INDEX_SIZE 512
typedef struct __packed {
    TPMI_RH_NV_LEGACY_INDEX nvIndex;
    TPMI_ALG_HASH nameAlg;
    TPMA_NV attributes;
    TPM2B_DIGEST authPolicy;
    UINT16 dataSize;  // {:MAX_NV_INDEX_SIZE}
} TPMS_NV_PUBLIC;

typedef struct __packed {
    UINT16 size;  // needs validation against actual size
    TPMS_NV_PUBLIC nvPublic;
} TPM2B_NV_PUBLIC;

typedef struct __packed {
    UINT32 PPWRITE             : 1;
    UINT32 OWNERWRITE          : 1;
    UINT32 AUTHWRITE           : 1;
    UINT32 POLICYWRITE         : 1;
    UINT32 TPM_NT              : 4;
    UINT32 Reserved_bits_at_8  : 2;
    UINT32 POLICY_DELETE       : 1;
    UINT32 WRITELOCKED         : 1;
    UINT32 WRITEALL            : 1;
    UINT32 WRITEDEFINE         : 1;
    UINT32 WRITE_STCLEAR       : 1;
    UINT32 GLOBALLOCK          : 1;
    UINT32 PPREAD              : 1;
    UINT32 OWNERREAD           : 1;
    UINT32 AUTHREAD            : 1;
    UINT32 POLICYREAD          : 1;
    UINT32 Reserved_bits_at_20 : 5;
    UINT32 NO_DA               : 1;
    UINT32 ORDERLY             : 1;
    UINT32 CLEAR_STCLEAR       : 1;
    UINT32 READLOCKED          : 1;
    UINT32 WRITTEN             : 1;
    UINT32 PLATFORMCREATE      : 1;
    UINT32 READ_STCLEAR        : 1;
} TPMA_NV;

typedef TPM2B_DIGEST TPM2B_AUTH;

// Headers
typedef struct __packed {
    TPMI_ST_COMMAND_TAG tag;
    UINT32 commandSize;
    TPM_CC commandCode;
} tpm_cmd_header_t;

typedef struct __packed {
    TPM_ST tag;
    UINT32 responseSize;
    TPM_RC responseCode;
} tpm_rsp_header_t;

// Input structures
typedef struct __packed {
    UINT16 bytesRequested;
} GetRandom_In;

typedef struct __packed {
    TPMI_RH_PROVISION authHandle;
    TPM2B_AUTH auth;
    TPM2B_NV_PUBLIC publicInfo;
} NV_DefineSpace_In;

// Output structures
typedef struct __packed {
    TPM2B_DIGEST randomBytes;
} GetRandom_Out;

/* Marshalling and unmarshalling layer */

// Endianness conversion functions
UINT8 read_be8(Fifo8 *fifo);
UINT16 read_be16(Fifo8 *fifo);
UINT32 read_be32(Fifo8 *fifo);
void write_be16(Fifo8 *fifo, UINT16 value);
void write_be32(Fifo8 *fifo, UINT32 value);

// Marshalling and unmarshalling functions
void tpm_cmd_header_unmarshal(Fifo8 *fifo, tpm_cmd_header_t *header);
void tpm_rsp_header_marshal(Fifo8 *fifo, const tpm_rsp_header_t *header);

// Command specific marshalling functions
void nv_define_space_in_unmarshal(Fifo8 *fifo, uint8_t *in);
void get_random_in_unmarshal(Fifo8 *fifo, uint8_t *in);
void get_random_out_marshal(Fifo8 *fifo, const uint8_t *out);

/* TPM Commands */

// Response functions
void tpm_error_response(S32k358TPMState *s, TPM_RC rc);
void tpm_success_response(S32k358TPMState *s, const uint8_t *data, size_t size, void marshal_func(Fifo8 *fifo, const uint8_t *data));

// TPM Commands
TPM_RC TPM2_GetRandom(GetRandom_In *in, GetRandom_Out *out);

// Non-volatile Storage
TPM_RC TPM2_NV_DefineSpace(NV_DefineSpace_In *in);

#endif

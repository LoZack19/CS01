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

// Basic definitions

typedef uint32_t TPM_CC;
#define TPM_CC_GetRandom 0x0000017B
#define TPM_CC_CreatePrimary 0x00000143

typedef uint32_t TPM_RC;
#define TPM_RC_SUCCESS 0x000
#define TPM_RC_BAD_TAG 0x01E
#define RC_VER1 0x100
#define TPM_RC_COMMAND_SIZE (RC_VER1 + 0x42)
#define TPM_RC_COMMAND_CODE (RC_VER1 + 0x43)

typedef uint16_t TPM_ST;
typedef uint16_t TPMI_ST_COMMAND_TAG;
#define TPM_ST_NO_SESSIONS 0x8001
#define TPM_ST_SESSIONS    0x8002

typedef uint8_t BYTE;
typedef uint16_t UINT16;
typedef uint32_t UINT32;

typedef TPM2B_DIGEST TPM2B_AUTH;

#define LABEL_MAX_BUFFER 1024
#define MAX_SYM_DATA 128
#define MAX_ECC_KEY_BYTES 32
#define MAX_RSA_KEY_BYTES 256

typedef UINT16 TPM_ALG_ID; 
typedef UINT16 TPM_KEY_BITS;         
typedef UINT32 TPMA_OBJECT;     

typedef TPM_ALG_ID  TPMI_ALG_PUBLIC; 
typedef TPM_ALG_ID  TPMI_ALG_HASH; 
typedef TPM_ALG_ID  TPMI_ALG_KEYEDHASH_SCHEME; 
typedef TPM_ALG_ID  TPMI_ALG_KDF;
typedef TPM_ALG_ID  TPMI_ALG_SYM_OBJECT;
typedef TPM_ALG_ID  TPMI_ALG_SYM_MODE;
typedef TPM_ALG_ID  TPMI_ALG_ASYM_SCHEME;
typedef TPM_ALG_ID  TPMI_ALG_RSA_SCHEME;

typedef TPM_KEY_BITS TPMI_RSA_KEY_BITS;

typedef TPMS_SCHEME_HASH TPMS_SCHEME_HMAC; 

// Structured types

#define SHA256_DIGEST_SIZE 32

typedef union __packed {
    BYTE sha256[SHA256_DIGEST_SIZE];
} TPMU_HA;

typedef struct __packed {
    UINT16 size;
    BYTE buffer[sizeof(TPMU_HA)];
} TPM2B_DIGEST;

typedef struct __packed {
    UINT16 size;
    BYTE buffer[sizeof(LABEL_MAX_BUFFER)];
} TPM2B_LABEL;

typedef struct __packed {
    TPM2B_LABEL label;
    TPM2B_LABEL context;
} TPMS_DERIVE;

typedef struct __packed {
    BYTE create[MAX_SYM_DATA];
    TPMS_DERIVE derive;
} TPMU_SENSITIVE_CREATE;

typedef struct __packed {
    UINT16 size;
    BYTE buffer[sizeof(TPMU_SENSITIVE_CREATE)];
} TPM2B_SENSITIVE_DATA;

typedef struct __packed {
    TPM2B_AUTH auth;
    TPM2B_SENSITIVE_DATA data;
} TPMS_SENSITIVE_CREATE;

typedef struct __packed {
    UINT16 size;
    TPMS_SENSITIVE_CREATE sensitive;
} TPM2B_SENSITIVE_CREATE;

typedef struct __packed {
    TPMI_ALG_HASH hashAlg;
} TPMS_SCHEME_HASH;

typedef struct __packed {
    TPMI_ALG_HASH hashAlg; 
    TPMI_ALG_KDF kdf; 
} TPMS_SCHEME_XOR;

typedef union __packed {
    TPMS_SCHEME_HMAC hmac;
    TPMS_SCHEME_XOR xor;
    null;
} TPMU_SCHEME_KEYEDHASH;

typedef struct __packed {
    TPMI_ALG_KEYEDHASH_SCHEME scheme; 
    TPMU_SCHEME_KEYEDHASH details; 
} TPMT_KEYEDHASH_SCHEME;

typedef struct __packed {
    TPMT_KEYEDHASH_SCHEME scheme; 
} TPMS_KEYEDHASH_PARMS;

typedef union __packed {
    TPM_KEY_BITS sym;
    TPMI_ALG_HASH xor;
    null;
} TPMU_SYM_KEY_BITS;

typedef union __packed {
    null;
} TPMU_SYM_DETAILS;

typedef union __packed {
    TPMI_ALG_SYM_MODE sym; // modalità standard
    null;
} TPMU_SYM_MODE;

typedef struct __packed {
    TPMI_ALG_SYM_OBJECT algorithm; 
    TPMU_SYM_KEY_BITS keyBits; 
    TPMU_SYM_MODE mode;
    TPMU_SYM_DETAILS details; 
} TPMT_SYM_DEF_OBJECT;

typedef struct __packed {
    TPMT_SYM_DEF_OBJECT sym; 
} TPMS_SYMCIPHER_PARMS;

typedef struct __packed {
    TPMI_ALG_RSA_SCHEME scheme;
    TPMU_ASYM_SCHEME details;
} TPMT_RSA_SCHEME;

typedef struct __packed {
    TPMT_SYM_DEF_OBJECT symmetric;
    TPMT_RSA_SCHEME scheme;
    TPMI_RSA_KEY_BITS keyBits;
    UINT32 exponent;
} TPMS_RSA_PARMS;

typedef struct __packed {
    UINT16 size;
    BYTE buffer[sizeof(MAX_ECC_KEY_BYTES)];
} TPM2B_ECC_PARAMETER;

typedef struct __packed {
    TPM2B_ECC_PARAMETER x;
    TPM2B_ECC_PARAMETER y;
} TPMS_ECC_PARMS;

typedef struct __packed {
    TPM2B_ECC_PARAMETER x;
    TPM2B_ECC_PARAMETER y;
} TPMS_ECC_POINT;

typedef union __packed {
    TPMS_SCHEME_HASH anySig;
    null;
} TPMU_ASYM_SCHEME;

typedef struct __packed {
    TPMI_ALG_ASYM_SCHEME scheme;
    TPMU_ASYM_SCHEME details;
} TPMT_ASYM_SCHEME;

typedef struct __packed {
    TPMT_SYM_DEF_OBJECT symmetric;
    TPMT_ASYM_SCHEME scheme;
} TPMS_ASYM_PARMS;

typedef union __packed {
    TPMS_KEYEDHASH_PARMS keyedHashDetail;
    TPMS_SYMCIPHER_PARMS symDetail;
    TPMS_RSA_PARMS rsaDetail;
    TPMS_ECC_PARMS eccDetail;
    TPMS_ASYM_PARMS asymDetail;
} TPMU_PUBLIC_PARMS;

typedef struct __packed {
    UINT16 size;
    BYTE buffer[sizeof(MAX_RSA_KEY_BYTES)];
} TPM2B_PUBLIC_KEY_RSA;

typedef struct __packed {
    UINT16 size;
    TPMS_ECC_POINT point;
} TPM2B_ECC_POINT;

typedef union __packed {
    TPM2B_DIGEST keyedHash;
    TPM2B_DIGEST sym;
    TPM2B_PUBLIC_KEY_RSA rsa;
    TPM2B_ECC_POINT ecc;
    TPMS_DERIVE derive;
} TPMU_PUBLIC_ID;

typedef struct __packed {
    TPMI_ALG_PUBLIC type; 
    TPMI_ALG_HASH nameAlg; 
    TPMA_OBJECT objectAttributes;
    TPM2B_DIGEST authPolicy;
    TPMU_PUBLIC_PARMS parameters;
    TPMU_PUBLIC_ID unique;
} TPMT_PUBLIC;

typedef struct __packed {
    UINT16 size;
    TPMT_PUBLIC publicArea;
} TPM2B_PUBLIC;

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

typedef struct __packed {
    UINT16 size;
    BYTE buffer[sizeof(TPMT_HA)];
} TPM2B_DATA;

typedef struct __packed {
    TPMI_ALG_HASH hashAlg;
    TPMU_HA digest;
} TPMT_HA;

typedef struct __packed {
    UINT32 count;
    TPMS_PCR_SELECTION pcrSelections[sizeof(HASH_COUNT)];
} TPML_PCR_SELECTION;

typedef struct __packed {
    TPMI_ALG_HASH hash;
    BYTE sizeofSelect;
    BYTE pcrSelect[sizeof(PCR_SELECT_MAX)];
} TPMS_PCR_SELECTION;

// Input structures
typedef struct __packed {
    UINT16 bytesRequested;
} GetRandom_In;

typedef struct __packed {
    TPM2B_SENSITIVE_CREATE inSensitive;
    TPM2B_PUBLIC inPublic;
    TPM2B_DATA outsideInfo;
    TPML_PCR_SELECTION creationPCR;
} CreatePrimary_In;

// Output structures
typedef struct __packed {
    TPM2B_DIGEST randomBytes;
} GetRandom_Out;

typedef struct __packed {
    TPM2B_PUBLIC outPublic;
    TPM2B_CREATION_DATA creationData;
    TPM2B_DIGEST creationHash;
    TPMT_TK_CREATION creationTicket;
} CreatePrimary_Out;

/* Marshalling and unmarshalling layer */

// Endianness conversion functions
UINT16 read_be16(Fifo8 *fifo);
UINT32 read_be32(Fifo8 *fifo);
void write_be16(Fifo8 *fifo, UINT16 value);
void write_be32(Fifo8 *fifo, UINT32 value);

// Marshalling and unmarshalling functions
void tpm_cmd_header_unmarshal(Fifo8 *fifo, tpm_cmd_header_t *header);
void tpm_rsp_header_marshal(Fifo8 *fifo, const tpm_rsp_header_t *header);

// Command specific marshalling functions
void get_random_in_unmarshal(Fifo8 *fifo, uint8_t *in);
void get_random_out_marshal(Fifo8 *fifo, const uint8_t *out);

/* TPM Commands */

// Response functions
void tpm_error_response(S32k358TPMState *s, TPM_RC rc);
void tpm_success_response(S32k358TPMState *s, const uint8_t *data, size_t size, void marshal_func(Fifo8 *fifo, const uint8_t *data));

// TPM Commands
TPM_RC TPM2_GetRandom(GetRandom_In *in, GetRandom_Out *out);

#endif

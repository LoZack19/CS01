#include <stdint.h>
#include "include/qemu/fifo8.h"

#define __packed __attribute__((packed))

/* Section #1: Constants */

// Size Configuration
#define SHA256_DIGEST_SIZE 32
#define MAX_NV_INDEX_SIZE 512
#define MAX_NV_BUFFER_SIZE 128

#define TPM_NT_ORDINARY 0x0
#define TPM_NT_COUNTER 0x1
#define TPM_NT_BITS 0x2
#define TPM_NT_EXTEND 0x4
#define TPM_NT_PIN_FAIL 0x8
#define TPM_NT_PIN_PASS 0x9

// TPM_RC
#define TPM_RC_SUCCESS          (TPM_RC)0x000
#define TPM_RC_H                (TPM_RC)(0x000)  /* Error due to handle */
#define TPM_RC_P                (TPM_RC)(0x040)  /* Error due to parameter */
#define TPM_RC_(n)              (TPM_RC)((n) << 8)
#define TPM_RC_1                (TPM_RC)(TPM_RC_(1))  /* first (modifier) */
#define TPM_RC_2                (TPM_RC)(TPM_RC_(2))  /* second (modifier) */
#define TPM_RC_3                (TPM_RC)(TPM_RC_(3))  /* third (modifier) */
#define TPM_RC_BAD_TAG          (TPM_RC)0x01E
#define RC_VER1                 (TPM_RC)0x100
#define TPM_RC_COMMAND_SIZE     (TPM_RC)(RC_VER1 + 0x42)
#define TPM_RC_COMMAND_CODE     (TPM_RC)(RC_VER1 + 0x43)
#define TPM_RC_NV_RANGE         (TPM_RC)(RC_VER1 + 0x46)
#define TPM_RC_NV_LOCKED        (TPM_RC)(RC_VER1 + 0x48)
#define TPM_RC_NV_AUTHORIZATION (TPM_RC)(RC_VER1 + 0x49)
#define TPM_RC_NV_SPACE         (TPM_RC)(RC_VER1 + 0x4B)
#define TPM_RC_NV_DEFINED       (TPM_RC)(RC_VER1 + 0x4C)
#define RC_FMT1                 (TPM_RC)(0x080)
#define TPM_RC_ATTRIBUTES       (TPM_RC)(RC_FMT1 + 0x002)
#define TPM_RCS_ATTRIBUTES      (TPM_RC)(RC_FMT1 + 0x002)
#define TPM_RC_VALUE            (TPM_RC)(RC_FMT1 + 0x004)
#define TPM_RCS_VALUE           (TPM_RC)(RC_FMT1 + 0x004)
#define TPM_RC_HIERARCHY        (TPM_RC)(RC_FMT1 + 0x005)
#define TPM_RCS_HIERARCHY       (TPM_RC)(RC_FMT1 + 0x005)
#define TPM_RC_HANDLE           (TPM_RC)(RC_FMT1 + 0x00B)
#define TPM_RCS_HANDLE          (TPM_RC)(RC_FMT1 + 0x00B)
#define TPM_RCS_SIZE            (TPM_RC)(RC_FMT1 + 0x015)

// TPM_RC Modifiers
#define RC_NV_DefineSpace_authHandle (TPM_RC_H + TPM_RC_1)
#define RC_NV_DefineSpace_auth       (TPM_RC_P + TPM_RC_1)
#define RC_NV_DefineSpace_publicInfo (TPM_RC_P + TPM_RC_2)

// TPM_ST
#define TPM_ST_NO_SESSIONS 0x8001
#define TPM_ST_SESSIONS    0x8002

// TPM_HANDLE
#define TPM_RH_OWNER 0x40000001
#define TPM_RH_UNASSIGNED 0x40000008
#define TPM_RH_PLATFORM 0x4000000C
#define TPM_HT_NV_INDEX 0x01
#define HR_SHIFT 24
#define HR_NV_INDEX (TPM_HT_NV_INDEX << HR_SHIFT)
#define NV_INDEX_FIRST (HR_NV_INDEX + 0)
#define NV_INDEX_LAST (NV_INDEX_FIRST + 0x00FFFFFF)

// TPM_CC
#define TPM_CC_GetRandom 0x0000017B
#define TPM_CC_NV_DefineSpace 0x0000012A

// TPMI_ALG_HASH
#define TPM_ALG_NULL 0x0010

// state_clear_data
#define shEnable_RESET TRUE
#define ehEnable_RESET TRUE
#define phEnableNV_RESET TRUE
#define platformAlg_RESET TPM_ALG_NULL
#define platformPolicy_RESET (TPM2B_DIGEST){0}
#define platformAuth_RESET (TPM2B_AUTH){0}

/* Section #2: Macros */

// Marshalling and Unmarshalling
#define UNMARSHAL(data, fifo) unmarshal(data, sizeof(*(data)), fifo)
#define MARSHAL(fifo, data) marshal(fifo, data, sizeof(*(data)))

// Access to bitfields
#define IS_ATTRIBUTE(a, type, b)    ((a.b) != 0)
#define SET_ATTRIBUTE(a, type, b)   (a.b = SET)
#define CLEAR_ATTRIBUTE(a, type, b) (a.b = CLEAR)
#define GET_ATTRIBUTE(a, type, b)   (a.b)

// TPMA_NV
#define GET_TPM_NT(attributes) GET_ATTRIBUTE(attributes, TPMA_NV, TPM_NT)
#define IsNvCounterIndex(attributes) (GET_TPM_NT(attributes) == TPM_NT_COUNTER)
#define IsNvBitsIndex(attributes) (GET_TPM_NT(attributes) == TPM_NT_BITS)
#define IsNvExtendIndex(attributes) (GET_TPM_NT(attributes) == TPM_NT_EXTEND)

/* Section #3: Basic Types*/

/* Subsection #3.1: Primitive Types */

#define SET TRUE
#define CLEAR FALSE
typedef uint8_t BOOL;
typedef uint8_t BYTE;
typedef uint8_t UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;

/* Subsection #3.2: Secondary Types*/

typedef UINT8 TPM_HT;

typedef UINT16 TPM_ST;
typedef UINT16 TPM_ALG_ID;

typedef UINT32 TPM_HANDLE;
typedef UINT32 NV_REF;
typedef UINT32 TPM_RC;
typedef UINT32 TPM_CC;

/* Subsection #3.3: Specializations of Secondary Types*/
typedef TPM_ST TPMI_ST_COMMAND_TAG;

typedef TPM_HANDLE TPMI_RH_PROVISION;
typedef TPM_HANDLE TPMI_RH_NV_LEGACY_INDEX;
typedef TPM_HANDLE TPMI_RH_NV_AUTH;
typedef TPM_HANDLE TPMI_RH_NV_INDEX;

typedef TPM_ALG_ID TPMI_ALG_HASH;

/* Section #4: Complex Types */

/** Defines the end-of-list marker for NV. The list terminator is a UINT32 of
 * zero, followed by the current value of s_maxCounter which is a 64-bit value.
 * The structure is defined as an array of 3 UINT32 values so that there is no
 * padding between the  UINT32 list end marker and the UINT64 maxCounter */
typedef UINT32 NV_LIST_TERMINATOR[3];

/* Subsection #4.1: Structured Types */

typedef union __packed {
    BYTE sha256[SHA256_DIGEST_SIZE];
} TPMU_HA;

typedef struct __packed {
    UINT16 size;
    BYTE buffer[sizeof(TPMU_HA)];
} TPM2B_DIGEST;

typedef TPM2B_DIGEST TPM2B_AUTH;

typedef struct __packed {
    UINT16 size;
    BYTE buffer[MAX_NV_BUFFER_SIZE];
} TPM2B_MAX_NV_BUFFER;

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
    TPMS_NV_PUBLIC publicArea;
    TPM2B_AUTH authValue;
} NV_INDEX;

typedef struct __packed {
    UINT32 size;
    TPM_HANDLE handle;
} NV_ENTRY_HEADER;

/* Subsection #4.2: Useful Additions */

// Command Header
typedef struct __packed {
    TPMI_ST_COMMAND_TAG tag;
    UINT32 commandSize;
    TPM_CC commandCode;
} tpm_cmd_header_t;

// Response Header
typedef struct __packed {
    TPM_ST tag;
    UINT32 responseSize;
    TPM_RC responseCode;
} tpm_rsp_header_t;

typedef struct __packed {
    /* Hierarchy Control */
    BOOL shEnable;
    BOOL ehEnable;
    BOOL phEnableNV;
    TPMI_ALG_HASH platformAlg;
    TPM2B_DIGEST platformPolicy;
    TPM2B_AUTH platformAuth;
    
    /* PCR (empty) */
    /* ACT (empty) */
} state_clear_data;

/* Section #5: IO Structs */

// GetRandom
typedef struct __packed {
    UINT16 bytesRequested;
} GetRandom_In;

typedef struct __packed {
    TPM2B_DIGEST randomBytes;
} GetRandom_Out;

// NV_DefineSpace
typedef struct __packed {
    TPMI_RH_PROVISION authHandle;
    TPM2B_AUTH auth;
    TPM2B_NV_PUBLIC publicInfo;
} NV_DefineSpace_In;

// NV_Write
typedef struct __packed {
    TPMI_RH_NV_AUTH     authHandle;
    TPMI_RH_NV_INDEX    nvIndex;
    TPM2B_MAX_NV_BUFFER data;
    UINT16              offset;
} NV_Write_In;

/* Section #6: Function Prototypes */

/* Subsection #6.1: Marshalling and Unmarshalling functions */

void unmarshal(void *data, size_t size, Fifo8 *fifo);
void marshal(Fifo8 *fifo, const void *data, size_t size);

/* Subsection #6.2: Helper Functions */

// NV Storage
NV_INDEX* NvGetIndexInfo(TPM_HANDLE nvHandle, NV_REF *locator);
TPM_RC NvWriteAccessChecks(TPM_HANDLE authHandle, TPM_HANDLE nvHandle,
                           TPMA_NV attributes);
TPM_RC NvWriteIndexData(NV_INDEX* nvIndex, UINT32 offset,
                        UINT32 size, void* data);
TPM_RC NvDefineSpace(
    TPMI_RH_PROVISION authHandle,
    TPM2B_AUTH* auth,
    TPMS_NV_PUBLIC* publicInfo,
    TPM_RC blameAuthHandle,
    TPM_RC blameAuth,
    TPM_RC blamePublic);
BOOL NvInit(void *memory, size_t size, state_clear_data *tpm_saved_state);

/* Subsection #6.3: TPM Commands */
TPM_RC TPM2_GetRandom(GetRandom_In *in, GetRandom_Out *out);
TPM_RC TPM2_NV_DefineSpace(NV_DefineSpace_In *in);
TPM_RC TPM2_NV_Write(NV_Write_In* in);
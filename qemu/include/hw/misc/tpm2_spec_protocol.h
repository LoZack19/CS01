/*
 * NOTE: This header is the source for the generated copy at
 * firmware/include/tpm2_spec_protocol.h. Keep changes in sync.
 */
#ifndef TPM2_SPEC_PROTOCOL_H
#define TPM2_SPEC_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include "include/qemu/fifo8.h"

#define __packed __attribute__((packed))

/* Section #1: Constants */

// Size Configuration
/* Cryptographic Primitives */
#define SHA256_DIGEST_SIZE      32
#define TPM_MAX_KEY_SIZE        256
#define TPM_MAX_DATA_SIZE       256
#define TPM_MAX_SIGNATURE_SIZE  256
#define TPM_MAX_IV_SIZE         16   /* TPM2B_IV uses AES block length */
#define TPM_MAX_MAX_BUFFER_SIZE 1024 /* Implementation-defined max buffer */
#define RSA_PRIVATE_SIZE        256  /* Supports up to RSA-2048 keys */
#define DRBG_SEED_SIZE_BYTES    256
#define DRBG_SEED_SIZE_WORDS    (DRBG_SEED_SIZE_BYTES / sizeof(uint64_t))
/* Key Lifecycle Management */
#define MAX_SYM_DATA     128
#define LABEL_MAX_BUFFER 32
#define HASH_COUNT       5 /* Implementation-defined; TODO: check */
/* PCRs: minimal implementation provides 24 PCR registers (0..23). */
#define TPM_PCR_COUNT      24
#define PLATFORM_PCR       (TPM_PCR_COUNT - 1)
#define IMPLEMENTATION_PCR (TPM_PCR_COUNT - 1)
#define PCR_SELECT_MAX     ((IMPLEMENTATION_PCR + 7) / 8) /* in bytes */
#define PCR_SELECT_MIN     ((PLATFORM_PCR + 7) / 8)       /* in bytes */
/* NV Memory */
#define MAX_NV_INDEX_SIZE  512
#define MAX_NV_BUFFER_SIZE 128

#define TPM_NT_ORDINARY 0x0
#define TPM_NT_COUNTER  0x1
#define TPM_NT_BITS     0x2
#define TPM_NT_EXTEND   0x4
#define TPM_NT_PIN_FAIL 0x8
#define TPM_NT_PIN_PASS 0x9

// TPM_RC
#define TPM_RC_SUCCESS          (TPM_RC)0x000
#define TPM_RC_H                (TPM_RC)(0x000) /* Error due to handle */
#define TPM_RC_P                (TPM_RC)(0x040) /* Error due to parameter */
#define TPM_RC_(n)              (TPM_RC)((n) << 8)
#define TPM_RC_1                (TPM_RC)(TPM_RC_(1)) /* first (modifier) */
#define TPM_RC_2                (TPM_RC)(TPM_RC_(2)) /* second (modifier) */
#define TPM_RC_3                (TPM_RC)(TPM_RC_(3)) /* third (modifier) */
#define TPM_RC_BAD_TAG          (TPM_RC)0x01E
#define RC_VER1                 (TPM_RC)0x100
#define TPM_RC_FAILURE          (TPM_RC)(RC_VER1 + 0x01)
#define TPM_RC_OBJECT_MEMORY    (TPM_RC)(RC_VER1 + 0x19)
#define TPM_RC_COMMAND_SIZE     (TPM_RC)(RC_VER1 + 0x42)
#define TPM_RC_COMMAND_CODE     (TPM_RC)(RC_VER1 + 0x43)
#define TPM_RC_NV_RANGE         (TPM_RC)(RC_VER1 + 0x46)
#define TPM_RC_NV_LOCKED        (TPM_RC)(RC_VER1 + 0x48)
#define TPM_RC_NV_AUTHORIZATION (TPM_RC)(RC_VER1 + 0x49)
#define TPM_RC_NV_UNINITIALIZED (TPM_RC)(RC_VER1 + 0x4A)
#define TPM_RC_NV_SPACE         (TPM_RC)(RC_VER1 + 0x4B)
#define TPM_RC_NV_DEFINED       (TPM_RC)(RC_VER1 + 0x4C)
#define RC_FMT1                 (TPM_RC)(0x080)
#define TPM_RC_ATTRIBUTES       (TPM_RC)(RC_FMT1 + 0x002)
#define TPM_RCS_ATTRIBUTES      (TPM_RC)(RC_FMT1 + 0x002)
#define TPM_RC_HASH             (TPM_RC)(RC_FMT1 + 0x003)
#define TPM_RCS_HASH            (TPM_RC)(RC_FMT1 + 0x003)
#define TPM_RC_VALUE            (TPM_RC)(RC_FMT1 + 0x004)
#define TPM_RCS_VALUE           (TPM_RC)(RC_FMT1 + 0x004)
#define TPM_RC_HIERARCHY        (TPM_RC)(RC_FMT1 + 0x005)
#define TPM_RCS_HIERARCHY       (TPM_RC)(RC_FMT1 + 0x005)
#define TPM_RC_MODE             (TPM_RC)(RC_FMT1 + 0x009)
#define TPM_RC_TYPE             (TPM_RC)(RC_FMT1 + 0x00A)
#define TPM_RCS_TYPE            (TPM_RC)(RC_FMT1 + 0x00A)
#define TPM_RC_HANDLE           (TPM_RC)(RC_FMT1 + 0x00B)
#define TPM_RCS_HANDLE          (TPM_RC)(RC_FMT1 + 0x00B)
#define TPM_RCS_SIZE            (TPM_RC)(RC_FMT1 + 0x015)
#define TPM_RC_SIGNATURE        (TPM_RC)(RC_FMT1 + 0x01B)
#define TPM_RC_KEY              (TPM_RC)(RC_FMT1 + 0x01C)
#define TPM_RC_BINDING          (TPM_RC)(RC_FMT1 + 0x022)
#define TPM_RCS_BINDING         (TPM_RC)(RC_FMT1 + 0x022)

// TPM_RC Modifiers
#define RC_NV_DefineSpace_authHandle (TPM_RC_H + TPM_RC_1)
#define RC_NV_DefineSpace_auth       (TPM_RC_P + TPM_RC_1)
#define RC_NV_DefineSpace_publicInfo (TPM_RC_P + TPM_RC_2)
#define RC_CreatePrimary_inPublic    (TPM_RC_P + TPM_RC_1)
#define RC_CreatePrimary_inSensitive (TPM_RC_P + TPM_RC_2)

// TPM_ST
#define TPM_ST_NO_SESSIONS 0x8001
#define TPM_ST_SESSIONS    0x8002
#define TPM_ST_CREATION    0x8021

// TPM_HANDLE
#define TPM_RH_OWNER                0x40000001
#define TPM_RH_NULL                 0x40000007
#define TPM_RH_UNASSIGNED           0x40000008
#define TPM_RH_ENDORSEMENT          0x4000000B
#define TPM_RH_PLATFORM             0x4000000C
#define TPM_RH_FW_OWNER             0x40000140
#define TPM_RH_FW_ENDORSEMENT       0x40000141
#define TPM_RH_FW_PLATFORM          0x40000142
#define TPM_RH_FW_NULL              0x40000143
#define TPM_RH_SVN_OWNER_BASE       0x40010000
#define TPM_RH_SVN_ENDORSEMENT_BASE 0x40020000
#define TPM_RH_SVN_PLATFORM_BASE    0x40030000
#define TPM_RH_SVN_NULL_BASE        0x40040000
#define TPM_HT_NV_INDEX             0x01
#define HR_SHIFT                    24
#define HR_NV_INDEX                 (TPM_HT_NV_INDEX << HR_SHIFT)
#define NV_INDEX_FIRST              (HR_NV_INDEX + 0)
#define NV_INDEX_LAST               (NV_INDEX_FIRST + 0x00FFFFFF)

// TPM_CC
#define TPM_CC_GetRandom 0x0000017B
/* NV Memory*/
#define TPM_CC_NV_DefineSpace 0x0000012A
#define TPM_CC_NV_Write       0x00000137
#define TPM_CC_NV_Read        0x0000014E
/* Cryptographic Primitives */
#define TPM_CC_Sign            0x0000015D
#define TPM_CC_VerifySignature 0x00000177
#define TPM_CC_Hash            0x0000017D
#define TPM_CC_EncryptDecrypt2 0x00000143
#define TPM_CC_RSA_Encrypt     0x00000173
#define TPM_CC_RSA_Decrypt     0x00000174
// TPM Key Life Cycle Management
#define TPM_CC_CreatePrimary 0x00000131
#define TPM_CC_Create        0x00000153
#define TPM_CC_Load          0x00000157

// TPMI_ALG_HASH
#define TPM_ALG_RSA      0x0001
#define TPM_ALG_TDES     0x0003
#define TPM_ALG_SHA1     0x0004
#define TPM_ALG_AES      0x0006
#define TPM_ALG_SHA256   0x000B
#define TPM_ALG_NULL     0x0010
#define TPM_ALG_SM4      0x0013
#define TPM_ALG_RSASSA   0x0014
#define TPM_ALG_CAMELLIA 0x0015
#define TPM_ALG_RSAPSS   0x0016
#define TPM_ALG_CTR      0x0040
#define TPM_ALG_XTS      0x0041
#define TPM_ALG_CBC      0x0042
#define TPM_ALG_CFB      0x0043
#define TPM_ALG_ECB      0x0044
#define TPM_ALG_OFB      0x0045

// Label context strings
#define PRIMARY_OBJECT_CREATION "PRIMARY"

// state_clear_data
#define shEnable_RESET    TRUE
#define ehEnable_RESET    TRUE
#define phEnableNV_RESET  TRUE
#define platformAlg_RESET TPM_ALG_NULL
#define platformPolicy_RESET \
    (TPM2B_DIGEST) {         \
        0                    \
    }
#define platformAuth_RESET \
    (TPM2B_AUTH) {         \
        0                  \
    }

/* Section #2: Macros */

// Marshalling and Unmarshalling
#define UNMARSHAL(data, fifo) unmarshal(data, sizeof(*(data)), fifo)
#define MARSHAL(fifo, data)   marshal(fifo, data, sizeof(*(data)))

// Access to bitfields
#define IS_ATTRIBUTE(a, type, b)    ((a.b) != 0)
#define SET_ATTRIBUTE(a, type, b)   (a.b = SET)
#define CLEAR_ATTRIBUTE(a, type, b) (a.b = CLEAR)
#define GET_ATTRIBUTE(a, type, b)   (a.b)

// TPMA_NV
#define GET_TPM_NT(attributes)       GET_ATTRIBUTE(attributes, TPMA_NV, TPM_NT)
#define IsNvCounterIndex(attributes) (GET_TPM_NT(attributes) == TPM_NT_COUNTER)
#define IsNvBitsIndex(attributes)    (GET_TPM_NT(attributes) == TPM_NT_BITS)
#define IsNvExtendIndex(attributes)  (GET_TPM_NT(attributes) == TPM_NT_EXTEND)

/* Section #3: Basic Types*/

/* Subsection #3.1: Primitive Types */

#define SET   TRUE
#define CLEAR FALSE
typedef uint8_t BOOL;
typedef uint8_t BYTE;
typedef uint8_t UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef uint64_t crypt_uword_t;
typedef BYTE TPMI_YES_NO;

/* Subsection #3.2: Secondary Types*/

typedef UINT8 TPM_HT;

typedef UINT16 TPM_ST;
typedef UINT16 TPM_ALG_ID;
typedef UINT16 TPM_KEY_BITS;

typedef union __packed {
    UINT16 sym;
    UINT16 aes;
    UINT16 sm4;
    UINT16 camellia;
    UINT16 tdes;
} TPMU_SYM_KEY_BITS;

typedef union __packed {
    UINT16 sym;
    UINT16 chainMode;
} TPMU_SYM_MODE;

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
typedef TPM_HANDLE TPMI_DH_OBJECT;
typedef TPM_HANDLE TPMI_RH_HIERARCHY;

typedef TPM_ALG_ID TPMI_ALG_HASH;
typedef TPM_ALG_ID TPMI_ALG_SYM_OBJECT;
typedef TPM_ALG_ID TPMI_ALG_SYM_MODE;
typedef TPM_ALG_ID TPMI_ALG_CIPHER_MODE;
typedef TPM_ALG_ID TPMI_ALG_SIG_SCHEME;
typedef TPM_ALG_ID TPMI_ALG_PUBLIC;
typedef TPM_ALG_ID TPMI_ALG_RSA_SCHEME;

typedef TPM_KEY_BITS TPMI_RSA_KEY_BITS;

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

// Generic TPM2B structure (variable-sized byte buffer)
typedef struct __packed {
    UINT16 size;
    BYTE buffer[sizeof(TPMU_HA)];
} TPM2B;

typedef struct __packed {
    UINT16 size;
    BYTE data[TPM_MAX_DATA_SIZE]; // Max data size for simplicity
} TPM2B_DATA;

typedef struct __packed {
    UINT16 signatureSize;
    BYTE signature[TPM_MAX_SIGNATURE_SIZE]; // Max signature size (supports
                                            // RSA-2048 signatures)
} TPM2B_SIGNATURE;

typedef struct __packed {
    UINT16 keySize;
    BYTE key[TPM_MAX_KEY_SIZE]; // Max key size
} TPM2B_KEY;

typedef struct {
    TPMI_ALG_HASH hashAlg;
    TPMU_HA digest;
} TPMT_HA;

typedef union __packed {
    TPMT_HA digest;
    TPM_HANDLE handle;
} TPMU_NAME;

typedef struct __packed {
    UINT16 size;
    BYTE buffer[sizeof(TPMU_HA)];
} TPM2B_DIGEST;

typedef TPM2B_DIGEST TPM2B_AUTH;

typedef struct __packed {
    TPMI_ALG_SIG_SCHEME scheme;
    TPMI_ALG_HASH hashAlg;
} TPMT_SIG_SCHEME;

typedef struct __packed {
    TPM_ST tag;
    TPM_HANDLE hierarchy;
    TPM2B_DIGEST digest;
} TPMT_TK_HASHCHECK;

typedef TPMT_TK_HASHCHECK TPMT_TK_VERIFIED;
typedef TPMT_TK_HASHCHECK TPMT_TK_CREATION;

typedef struct __packed {
    TPMI_ALG_SIG_SCHEME sigAlg;
    TPMI_ALG_HASH hashAlg;
    TPM2B_SIGNATURE signature;
} TPMT_SIGNATURE;

typedef struct __packed {
    TPMI_ALG_SYM_OBJECT algorithm; // TPM_ALG_* algorithm (AES, SM4, etc.)
    TPMU_SYM_KEY_BITS keyBits;     // Key size in bits (per algorithm)
    TPMU_SYM_MODE mode;            // Mode selector (ECB, CBC, CFB, OFB, CTR)
} TPMT_SYM_DEF_OBJECT;

typedef struct __packed {
    UINT16 ivSize;
    BYTE iv[TPM_MAX_IV_SIZE]; // Max IV size for AES
} TPM2B_IV;

typedef struct __packed {
    UINT16 bufferSize;
    BYTE buffer[TPM_MAX_MAX_BUFFER_SIZE]; // Larger buffer for symmetric
                                          // operations
} TPM2B_MAX_BUFFER;

typedef struct __packed {
    UINT16 size;
    BYTE buffer[TPM_MAX_KEY_SIZE];
} TPM2B_PUBLIC_KEY_RSA;

typedef struct __packed {
    UINT16 size;
    BYTE buffer[MAX_NV_BUFFER_SIZE];
} TPM2B_MAX_NV_BUFFER;

typedef struct __packed {
    UINT16 size;
    BYTE buffer[sizeof(TPMU_NAME)];
} TPM2B_NAME;

typedef struct __packed {
    UINT16 size;
    BYTE buffer[TPM_MAX_MAX_BUFFER_SIZE];
} TPM2B_CREATION_DATA;

typedef struct __packed {
    UINT32 PPWRITE : 1;
    UINT32 OWNERWRITE : 1;
    UINT32 AUTHWRITE : 1;
    UINT32 POLICYWRITE : 1;
    UINT32 TPM_NT : 4;
    UINT32 Reserved_bits_at_8 : 2;
    UINT32 POLICY_DELETE : 1;
    UINT32 WRITELOCKED : 1;
    UINT32 WRITEALL : 1;
    UINT32 WRITEDEFINE : 1;
    UINT32 WRITE_STCLEAR : 1;
    UINT32 GLOBALLOCK : 1;
    UINT32 PPREAD : 1;
    UINT32 OWNERREAD : 1;
    UINT32 AUTHREAD : 1;
    UINT32 POLICYREAD : 1;
    UINT32 Reserved_bits_at_20 : 5;
    UINT32 NO_DA : 1;
    UINT32 ORDERLY : 1;
    UINT32 CLEAR_STCLEAR : 1;
    UINT32 READLOCKED : 1;
    UINT32 WRITTEN : 1;
    UINT32 PLATFORMCREATE : 1;
    UINT32 READ_STCLEAR : 1;
} TPMA_NV;

typedef struct __packed {
    UINT32 Reserved0 : 1; /* Shall be 0*/
    UINT32 fixedTPM : 1;
    UINT32 stClear : 1;
    UINT32 Reserved1 : 1;
    UINT32 fixedParent : 1;
    UINT32 sensitiveDataOrigin : 1;
    UINT32 userWithAuth : 1;
    UINT32 adminWithPolicy : 1;
    UINT32 firmwareLimited : 1;
    UINT32 svnLimited : 1;
    UINT32 noDA : 1;
    UINT32 encryptedDuplication : 1;
    UINT32 Reserved2 : 4;
    UINT32 restricted : 1;
    UINT32 decrypt : 1;
    UINT32 sign_encrypt : 1;
    UINT32 x509sign : 1;
    UINT32 Reserved3 : 12;
} TPMA_OBJECT;

typedef struct __packed {
    TPMI_RH_NV_LEGACY_INDEX nvIndex;
    TPMI_ALG_HASH nameAlg;
    TPMA_NV attributes;
    TPM2B_DIGEST authPolicy;
    UINT16 dataSize; // {:MAX_NV_INDEX_SIZE}
} TPMS_NV_PUBLIC;

typedef struct __packed {
    UINT16 size; // needs validation against actual size
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

typedef struct __packed {
    UINT16 size;
    BYTE buffer[LABEL_MAX_BUFFER];
} TPM2B_LABEL;

typedef struct __packed {
    TPM2B_LABEL label;
    TPM2B_LABEL context;
} TPMS_DERIVE;

typedef union __packed {
    BYTE create[MAX_SYM_DATA];
    TPMS_DERIVE derive;
} TPMU_SENSITIVE_CREATE;

typedef struct __packed {
    UINT16 size;
    BYTE buffer[sizeof(TPMU_SENSITIVE_CREATE)];
} _TPM2B_SENSITIVE_DATA_BUFFER;

typedef union __packed {
    _TPM2B_SENSITIVE_DATA_BUFFER t;
    _TPM2B_SENSITIVE_DATA_BUFFER b;
    struct {
        UINT16 size;
        BYTE buffer[sizeof(TPMU_SENSITIVE_CREATE)];
    };
} TPM2B_SENSITIVE_DATA;

typedef struct __packed {
    TPM2B_AUTH userAuth;
    TPM2B_SENSITIVE_DATA data;
} TPMS_SENSITIVE_CREATE;

typedef struct __packed {
    UINT16 size;
    TPMS_SENSITIVE_CREATE sensitive;
} TPM2B_SENSITIVE_CREATE;

typedef struct __packed {
    TPMI_ALG_HASH hashAlg;
} TPMS_SCHEME_HASH;

typedef union __packed {
    TPMS_SCHEME_HASH anySig;
} TPMU_ASYM_SCHEME;

typedef struct __packed {
    TPMI_ALG_RSA_SCHEME scheme;
    TPMU_ASYM_SCHEME details;
} TPMT_RSA_SCHEME;

typedef struct __packed {
    TPMT_SYM_DEF_OBJECT symmetric;
    TPMT_RSA_SCHEME scheme;
    TPMI_RSA_KEY_BITS keyBits;
    UINT32 exponent;
} TPMS_RSA_PARAMS;

typedef struct __packed {
    // TPMS_KEYDHASH_PARAMS keyedHashDetail;
    // TPMS_SYMCIPHER_PARAMS symDetail;
    TPMS_RSA_PARAMS rsaDetail;
    // TPMS_ECC_PARAMS eccDetail;
    // TPMS_ASYM_PARAMS asymDetail;
} TPMU_PUBLIC_PARAMS;

typedef struct __packed {
    TPM2B_DIGEST keyedHash;
    TPM2B_DIGEST sym;
    TPM2B_PUBLIC_KEY_RSA rsa;
    // TPMS_ECC_POINT ecc;
    TPMS_DERIVE derive;
} TPMU_PUBLIC_ID;

typedef struct __packed {
    TPMI_ALG_PUBLIC type;
    TPMI_ALG_HASH nameAlg;
    TPMA_OBJECT objectAttributes;
    TPM2B_DIGEST authPolicy;
    TPMU_PUBLIC_PARAMS parameters; /*[type]*/
    TPMU_PUBLIC_ID unique;         /*[type]*/
} TPMT_PUBLIC;

typedef struct __packed {
    UINT16 size;
    TPMT_PUBLIC publicArea;
} TPM2B_PUBLIC;

typedef struct __packed {
    TPMI_ALG_HASH hash;
    UINT8 sizeofSelect; /* lower bound PCR_SELECT_MIN */
    BYTE pcrSelect[PCR_SELECT_MAX];
} TPMS_PCR_SELECTION;

typedef struct __packed {
    UINT32 count;
    TPMS_PCR_SELECTION pcrSelections[HASH_COUNT];
} TPML_PCR_SELECTION;

/* DRBG (Deterministic Random Bit Generator) Definitions */
// AES-based DRBG configuration
#define AES_MAX_KEY_SIZE_BITS 256
#define AES_MAX_BLOCK_SIZE    16

#define DRBG_KEY_SIZE_BITS AES_MAX_KEY_SIZE_BITS
#define DRBG_IV_SIZE_BITS  (AES_MAX_BLOCK_SIZE * 8)

#define RADIX_BITS  64
#define RADIX_BYTES (RADIX_BITS / 8)

#define BITS_TO_CRYPT_WORDS(bits) (((bits) + RADIX_BITS - 1) / RADIX_BITS)

#define DRBG_KEY_SIZE_WORDS BITS_TO_CRYPT_WORDS(DRBG_KEY_SIZE_BITS)
#define DRBG_KEY_SIZE_BYTES (DRBG_KEY_SIZE_WORDS * RADIX_BYTES)

#define DRBG_IV_SIZE_WORDS BITS_TO_CRYPT_WORDS(DRBG_IV_SIZE_BITS)
#define DRBG_IV_SIZE_BYTES (DRBG_IV_SIZE_WORDS * RADIX_BYTES)

/* Note: DRBG_SEED_SIZE_* are already defined at the top of this file (lines
 * 25-26) with fixed values (256 bytes). The computed values would be KEY+IV
 * (~48 bytes), but the fixed 256-byte value is used for the DRBG_SEED buffer
 * size. */

typedef union {
    BYTE bytes[DRBG_KEY_SIZE_BYTES];
    crypt_uword_t words[DRBG_KEY_SIZE_WORDS];
} DRBG_KEY;

typedef union {
    BYTE bytes[DRBG_IV_SIZE_BYTES];
    crypt_uword_t words[DRBG_IV_SIZE_WORDS];
} DRBG_IV;

typedef union {
    BYTE bytes[DRBG_SEED_SIZE_BYTES];
    crypt_uword_t words[DRBG_SEED_SIZE_WORDS];
} DRBG_SEED;

typedef struct __packed {
    UINT64 reseedCounter;
    UINT32 magic;
    DRBG_SEED seed;
    UINT32 lastValue[4];
} DRBG_STATE;

typedef DRBG_STATE RAND_STATE;

typedef struct __packed {
    uint16_t size;
    uint8_t buffer[64];
} _TPM2B_SEED_BUFFER;

typedef union {
    _TPM2B_SEED_BUFFER b;
    struct {
        uint16_t size;
        uint8_t buffer[64];
    };
} TPM2B_SEED;

typedef struct __packed {
    unsigned publicOnly : 1;
    unsigned epsHierarchy : 1;
    unsigned ppsHierarchy : 1;
    unsigned spsHierarchy : 1;
    unsigned evict : 1;
    unsigned primary : 1;
    unsigned temporary : 1;
    unsigned stClear : 1;
    unsigned hmacSeq : 1;
    unsigned hashSeq : 1;
    unsigned eventSeq : 1;
    unsigned ticketSafe : 1;
    unsigned firstBlock : 1;
    unsigned isParent : 1;
    unsigned not_used_14 : 1;
    unsigned occupied : 1;
    unsigned derivation : 1;
    unsigned external : 1;
} OBJECT_ATTRIBUTES;

typedef struct __packed {
    UINT16 size;
    BYTE buffer[RSA_PRIVATE_SIZE];
} TPM2B_PRIVATE_KEY_RSA;

typedef union __packed {
    TPM2B_PRIVATE_KEY_RSA rsa;
    // TPM2B_ECC_PARAMETER ecc;
    // TPM2B_SENSITIVE_DATA bits;
    // TPM2B_SYM_KEY sym;
    // TPM2B_PRIVATE_VENDOR_SPECIFIC any;
} TPMU_SENSITIVE_COMPOSITE;

typedef struct __packed {
    TPMI_ALG_PUBLIC sensitiveType;
    TPM2B_AUTH authValue;
    TPM2B_DIGEST seedValue;
    TPMU_SENSITIVE_COMPOSITE sensitive;
} TPMT_SENSITIVE;

/*
 * TPM2B_PRIVATE – Encrypted private area blob.
 *
 * The maximum size is implementation-defined.  We use a buffer large
 * enough to hold a marshaled TPMT_SENSITIVE plus integrity + IV
 * overhead (simplified model: just the raw TPMT_SENSITIVE bytes).
 */
#define MAX_PRIVATE_SIZE (sizeof(TPMT_SENSITIVE) + SHA256_DIGEST_SIZE + 16)

typedef struct __packed {
    UINT16 size;
    BYTE buffer[sizeof(TPMT_SENSITIVE) + SHA256_DIGEST_SIZE + 16];
} _TPM2B_PRIVATE_BUFFER;

typedef union {
    _TPM2B_PRIVATE_BUFFER b;
    struct {
        UINT16 size;
        BYTE buffer[sizeof(TPMT_SENSITIVE) + SHA256_DIGEST_SIZE + 16];
    };
} TPM2B_PRIVATE;

typedef struct __packed {
    OBJECT_ATTRIBUTES attributes;
    TPMT_PUBLIC publicArea;
    TPMT_SENSITIVE sensitive;
    TPM2B_NAME qualifiedName;
    TPMI_DH_OBJECT evictHandle;
    TPM2B_NAME name;
    TPMI_RH_HIERARCHY hierarchy;
} OBJECT;

/*
 * Authorization structures for TPM_ST_SESSIONS commands.
 *
 * TPMS_AUTH_COMMAND – Authorization area in command (after parameters).
 * TPMS_AUTH_RESPONSE – Authorization area in response (after parameters).
 *
 * Reference: TPM 2.0 Part 1, Tables 75-76 (Authorization)
 */
typedef struct __packed {
    UINT32 sessionHandle;   /* TPM_RS_PW for password sessions */
    TPM2B_DIGEST nonce;     /* Empty for password auth */
    BYTE sessionAttributes; /* Session attribute bits */
    TPM2B_AUTH hmac;        /* Password or HMAC */
} TPMS_AUTH_COMMAND;

typedef struct __packed {
    TPM2B_DIGEST nonce;     /* Empty for password auth */
    BYTE sessionAttributes; /* Session attribute bits */
    TPM2B_AUTH hmac;        /* Empty for password auth */
} TPMS_AUTH_RESPONSE;

/* Password authorization pseudo-handle */
#define TPM_RS_PW 0x40000009

/*
 * Wire-format auth areas (authSize prefix + content).
 * Used with MARSHAL/UNMARSHAL — no manual byte encoding needed.
 */
typedef struct __packed {
    UINT32 authSize;            /* sizeof(TPMS_AUTH_COMMAND) */
    TPMS_AUTH_COMMAND auth;
} TPMS_AUTH_COMMAND_AREA;

typedef struct __packed {
    UINT32 authSize;            /* sizeof(TPMS_AUTH_RESPONSE) */
    TPMS_AUTH_RESPONSE auth;
} TPMS_AUTH_RESPONSE_AREA;

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

    /* PCR: SHA-256 bank (minimal) */
    BYTE pcr_sha256[TPM_PCR_COUNT][SHA256_DIGEST_SIZE];
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
    TPMI_RH_NV_AUTH authHandle;
    TPMI_RH_NV_INDEX nvIndex;
    TPM2B_MAX_NV_BUFFER data;
    UINT16 offset;
} NV_Write_In;

// NV_Read
typedef struct __packed {
    TPMI_RH_NV_AUTH authHandle;
    TPMI_RH_NV_INDEX nvIndex;
    UINT16 size;
    UINT16 offset;
} NV_Read_In;

typedef struct __packed {
    TPM2B_MAX_NV_BUFFER data;
} NV_Read_Out;

// Sign
typedef struct __packed {
    TPM_HANDLE keyHandle;
    TPMT_SIG_SCHEME inScheme;
    TPM2B_DIGEST digest;
    TPMT_TK_HASHCHECK validation;
} Sign_In;

typedef struct __packed {
    TPMT_SIGNATURE signature;
} Sign_Out;

// VerifySignature
typedef struct __packed {
    TPM_HANDLE keyHandle;
    TPM2B_DIGEST digest;
    TPMT_SIGNATURE signature;
} VerifySignature_In;

typedef struct __packed {
    TPMT_TK_VERIFIED validation;
} VerifySignature_Out;

// Hash
typedef struct __packed {
    TPM2B_MAX_BUFFER data;
    TPMI_ALG_HASH hashAlg;
    TPMI_RH_HIERARCHY hierarchy;
} Hash_In;

typedef struct __packed {
    TPM2B_DIGEST digest;
    TPMT_TK_HASHCHECK validation;
} Hash_Out;

// EncryptDecrypt2
typedef struct __packed {
    TPMI_DH_OBJECT keyHandle;  // Symmetric key handle
    TPMI_YES_NO decrypt;       // 0=encrypt, 1=decrypt
    TPMI_ALG_CIPHER_MODE mode; // Mode selector (ECB, CBC, CFB, OFB, CTR)
    TPM2B_IV ivIn;             // Input IV (for chaining modes)
    TPM2B_MAX_BUFFER inData;   // Data to encrypt/decrypt
} EncryptDecrypt2_In;

typedef struct __packed {
    TPM2B_MAX_BUFFER outData; // Encrypted/decrypted data
    TPM2B_IV ivOut;           // Output IV (for chaining modes)
} EncryptDecrypt2_Out;

// RSA_Encrypt
typedef struct __packed {
    TPM_HANDLE keyHandle;
    TPM2B_PUBLIC_KEY_RSA message;
} RSA_Encrypt_In;

typedef struct __packed {
    TPM2B_PUBLIC_KEY_RSA encrypted;
} RSA_Encrypt_Out;

// RSA_Decrypt
typedef struct __packed {
    TPM_HANDLE keyHandle;
    TPM2B_PUBLIC_KEY_RSA encrypted;
} RSA_Decrypt_In;

typedef struct __packed {
    TPM2B_PUBLIC_KEY_RSA decrypted;
} RSA_Decrypt_Out;

// CreatePrimary

typedef struct __packed {
    TPMI_RH_HIERARCHY primaryHandle;
    TPM2B_SENSITIVE_CREATE inSensitive;
    TPM2B_PUBLIC inPublic;
    TPM2B_DATA outsideInfo;
    TPML_PCR_SELECTION creationPCR;
} CreatePrimary_In;

typedef struct __packed {
    TPM_HANDLE objectHandle;
    TPM2B_PUBLIC outPublic;
    TPM2B_CREATION_DATA creationData;
    TPM2B_DIGEST creationHash;
    TPMT_TK_CREATION creationTicket;
    TPM2B_NAME name;
} CreatePrimary_Out;

// Create (TPM2_Create – creates an object under a parent but does NOT load it)

#define RC_Create_parentHandle (TPM_RC_H + TPM_RC_1)
#define RC_Create_inSensitive  (TPM_RC_P + TPM_RC_1)
#define RC_Create_inPublic     (TPM_RC_P + TPM_RC_2)

typedef struct __packed {
    TPMI_DH_OBJECT parentHandle;
    TPM2B_SENSITIVE_CREATE inSensitive;
    TPM2B_PUBLIC inPublic;
    TPM2B_DATA outsideInfo;
    TPML_PCR_SELECTION creationPCR;
} Create_In;

typedef struct __packed {
    TPM2B_PRIVATE outPrivate;
    TPM2B_PUBLIC outPublic;
    TPM2B_CREATION_DATA creationData;
    TPM2B_DIGEST creationHash;
    TPMT_TK_CREATION creationTicket;
} Create_Out;

// Load (TPM2_Load – loads a key created by TPM2_Create)

#define RC_Load_parentHandle (TPM_RC_H + TPM_RC_1)
#define RC_Load_inPrivate    (TPM_RC_P + TPM_RC_1)
#define RC_Load_inPublic     (TPM_RC_P + TPM_RC_2)

typedef struct __packed {
    TPMI_DH_OBJECT parentHandle;
    TPM2B_PRIVATE inPrivate;
    TPM2B_PUBLIC inPublic;
} Load_In;

typedef struct __packed {
    TPM_HANDLE objectHandle;
    TPM2B_NAME name;
} Load_Out;

/* Section #6: Function Prototypes */

/* Subsection #6.1: Marshalling and Unmarshalling functions */

void unmarshal(void *data, size_t size, Fifo8 *fifo);
void marshal(Fifo8 *fifo, const void *data, size_t size);

/* Subsection #6.2: Helper Functions */

// NV Storage
NV_INDEX *NvGetIndexInfo(TPM_HANDLE nvHandle, NV_REF *locator);
TPM_RC NvWriteAccessChecks(TPM_HANDLE authHandle, TPM_HANDLE nvHandle,
                           TPMA_NV attributes);
TPM_RC NvWriteIndexData(NV_INDEX *nvIndex, UINT32 offset, UINT32 size,
                        void *data);
TPM_RC NvReadAccessChecks(TPM_HANDLE authHandle, TPM_HANDLE nvHandle,
                          TPMA_NV attributes);
void NvGetIndexData(NV_INDEX *nvIndex, NV_REF locator, UINT32 offset,
                    UINT16 size, void *data);

TPM_RC NvDefineSpace(TPMI_RH_PROVISION authHandle, TPM2B_AUTH *auth,
                     TPMS_NV_PUBLIC *publicInfo, TPM_RC blameAuthHandle,
                     TPM_RC blameAuth, TPM_RC blamePublic);
BOOL NvInit(void *memory, size_t size, state_clear_data *tpm_saved_state);

/* Subsection #6.3: TPM Commands */
TPM_RC TPM2_GetRandom(GetRandom_In *in, GetRandom_Out *out);
/* Cryptographic Primitives */
TPM_RC TPM2_Sign(Sign_In *in, Sign_Out *out);
TPM_RC TPM2_VerifySignature(VerifySignature_In *in, VerifySignature_Out *out);
TPM_RC TPM2_Hash(Hash_In *in, Hash_Out *out);
TPM_RC TPM2_EncryptDecrypt2(EncryptDecrypt2_In *in, EncryptDecrypt2_Out *out);
TPM_RC TPM2_RSA_Encrypt(RSA_Encrypt_In *in, RSA_Encrypt_Out *out);
TPM_RC TPM2_RSA_Decrypt(RSA_Decrypt_In *in, RSA_Decrypt_Out *out);
/* Key Lifecycle Management */
TPM_RC TPM2_CreatePrimary(CreatePrimary_In *in, CreatePrimary_Out *out);
TPM_RC TPM2_Create(Create_In *in, Create_Out *out);
TPM_RC TPM2_Load(Load_In *in, Load_Out *out);
/* NV Memory */
TPM_RC TPM2_NV_DefineSpace(NV_DefineSpace_In *in);
TPM_RC TPM2_NV_Write(NV_Write_In *in);
TPM_RC TPM2_NV_Read(NV_Read_In *in, NV_Read_Out *out);

#endif /* TPM2_SPEC_PROTOCOL_H */
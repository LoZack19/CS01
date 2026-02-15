/**
 * @file tpm2_spec_protocol.h
 * @brief Complete TPM 2.0 type system, constants, and command I/O structures.
 *
 * This header is the **single source of truth** for all TPM protocol
 * definitions used by both the firmware and the QEMU device model.
 * Firmware includes this header directly; the QEMU copy is generated
 * from it during the build.
 *
 * Organisation follows the TPM 2.0 spec structure:
 *   - §1 Constants  — size limits, return codes, handles, algorithms
 *   - §2 Macros     — marshal/unmarshal, attribute access helpers
 *   - §3 Basic Types — primitive and secondary typedefs
 *   - §4 Complex Types — hash, signature, symmetric, RSA, PCR, NV,
 *                         key/object, auth, DRBG, command headers, state
 *   - §5 Command I/O — per-command *_In / *_Out structures
 *   - §6 Function Prototypes — TPM command entry points
 *
 * @note Uses @c __packed to match TCG wire layout.
 * @note The firmware uses **native** endianness for MMIO transfers
 *       (intentional simplification; see project spec §3.1.2).
 */
#ifndef TPM2_SPEC_PROTOCOL_H
#define TPM2_SPEC_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include "fifo8.h"

/** @cond INTERNAL */
#define __packed __attribute__((packed))
/** @endcond */

/* ====================================================================== */
/** @defgroup tpm2_constants §1 Constants
 *  Size limits, return codes, handles, command codes, algorithms.
 *  @{ */
/* ====================================================================== */

/* ---- Size configuration ------------------------------------------------ */

/** @name Cryptographic size limits */
/** @{ */
#define SHA256_DIGEST_SIZE      32
#define TPM_MAX_KEY_SIZE        256
#define TPM_MAX_DATA_SIZE       256
#define TPM_MAX_SIGNATURE_SIZE  256
#define TPM_MAX_IV_SIZE         16   /* TPM2B_IV uses AES block length */
#define TPM_MAX_MAX_BUFFER_SIZE 1024 /* Implementation-defined max buffer */
#define RSA_PRIVATE_SIZE        256  /* Supports up to RSA-2048 keys */
#define MAX_PRIVATE_SIZE        (sizeof(TPMT_SENSITIVE) + SHA256_DIGEST_SIZE + 16)
/** @} */  /* Cryptographic size limits */

/** @name DRBG (Deterministic Random Bit Generator) parameters */
/** @{ */
#define DRBG_SEED_SIZE_BYTES      256
#define DRBG_SEED_SIZE_WORDS      (DRBG_SEED_SIZE_BYTES / sizeof(uint64_t))
#define AES_MAX_KEY_SIZE_BITS     256
#define AES_MAX_BLOCK_SIZE        16
#define DRBG_KEY_SIZE_BITS        AES_MAX_KEY_SIZE_BITS
#define DRBG_IV_SIZE_BITS         (AES_MAX_BLOCK_SIZE * 8)
#define RADIX_BITS                64
#define RADIX_BYTES               (RADIX_BITS / 8)
#define BITS_TO_CRYPT_WORDS(bits) (((bits) + RADIX_BITS - 1) / RADIX_BITS)
#define DRBG_KEY_SIZE_WORDS       BITS_TO_CRYPT_WORDS(DRBG_KEY_SIZE_BITS)
#define DRBG_KEY_SIZE_BYTES       (DRBG_KEY_SIZE_WORDS * RADIX_BYTES)
#define DRBG_IV_SIZE_WORDS        BITS_TO_CRYPT_WORDS(DRBG_IV_SIZE_BITS)
#define DRBG_IV_SIZE_BYTES        (DRBG_IV_SIZE_WORDS * RADIX_BYTES)
/** @} */  /* DRBG */

/** @name Key lifecycle management limits */
/** @{ */
#define MAX_SYM_DATA     128
#define LABEL_MAX_BUFFER 32
#define HASH_COUNT       5 /* Implementation-defined; TODO: check */
/** @} */  /* Key lifecycle */

/** @name PCR configuration */
/** @{ */
#define TPM_PCR_COUNT      24
#define PLATFORM_PCR       (TPM_PCR_COUNT - 1)
#define IMPLEMENTATION_PCR (TPM_PCR_COUNT - 1)
#define PCR_SELECT_MAX     ((IMPLEMENTATION_PCR + 7) / 8) /* in bytes */
#define PCR_SELECT_MIN     ((PLATFORM_PCR + 7) / 8)       /* in bytes */
/** @} */  /* PCR configuration */

/** @name NV memory limits and index types */
/** @{ */
#define MAX_NV_INDEX_SIZE  512
#define MAX_NV_BUFFER_SIZE 128

#define TPM_NT_ORDINARY 0x0
#define TPM_NT_COUNTER  0x1
#define TPM_NT_BITS     0x2
#define TPM_NT_EXTEND   0x4
#define TPM_NT_PIN_FAIL 0x8
#define TPM_NT_PIN_PASS 0x9
/** @} */  /* NV memory */

/** @name TPM_RC — Response codes (TCG Part 2, Table 16) */
/** @{ */
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
#define TPM_RC_INITIALIZE       (TPM_RC)(RC_VER1 + 0x00)
#define TPM_RC_OBJECT_MEMORY    (TPM_RC)(RC_VER1 + 0x19)
#define TPM_RC_COMMAND_SIZE     (TPM_RC)(RC_VER1 + 0x42)
#define TPM_RC_COMMAND_CODE     (TPM_RC)(RC_VER1 + 0x43)
#define TPM_RC_NV_RANGE         (TPM_RC)(RC_VER1 + 0x46)
#define TPM_RC_NV_LOCKED        (TPM_RC)(RC_VER1 + 0x48)
#define TPM_RC_NV_AUTHORIZATION (TPM_RC)(RC_VER1 + 0x49)
#define TPM_RC_NV_UNINITIALIZED (TPM_RC)(RC_VER1 + 0x4A)
#define TPM_RC_NV_SPACE         (TPM_RC)(RC_VER1 + 0x4B)
#define TPM_RC_NV_DEFINED       (TPM_RC)(RC_VER1 + 0x4C)
#define TPM_RC_UPGRADE          (TPM_RC)(RC_VER1 + 0x2D)
#define TPM_RC_REBOOT           (TPM_RC)(RC_VER1 + 0x30)
#define TPM_RC_READ_ONLY        (TPM_RC)(RC_VER1 + 0x56)
#define RC_FMT1                 (TPM_RC)(0x080)
#define TPM_RC_ATTRIBUTES       (TPM_RC)(RC_FMT1 + 0x002)
#define TPM_RCS_ATTRIBUTES      (TPM_RC)(RC_FMT1 + 0x002)
#define TPM_RC_HASH             (TPM_RC)(RC_FMT1 + 0x003)
#define TPM_RCS_HASH            (TPM_RC)(RC_FMT1 + 0x003)
#define TPM_RC_VALUE            (TPM_RC)(RC_FMT1 + 0x004)
#define TPM_RCS_VALUE           (TPM_RC)(RC_FMT1 + 0x004)
#define TPM_RC_HIERARCHY        (TPM_RC)(RC_FMT1 + 0x005)
#define TPM_RCS_HIERARCHY       (TPM_RC)(RC_FMT1 + 0x005)
#define TPM_RC_KEY_SIZE         (TPM_RC)(RC_FMT1 + 0x007)
#define TPM_RC_SCHEME           (TPM_RC)(RC_FMT1 + 0x008)
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
#define TPM_RC_SEQUENCE         (TPM_RC)(RC_FMT1 + 0x023)
/** @} */  /* TPM_RC */

/** @name TPM_RC parameter/handle modifiers */
/** @{ */
// TPM_RC Modifiers
#define RC_NV_DefineSpace_authHandle (TPM_RC_H + TPM_RC_1)
#define RC_NV_DefineSpace_auth       (TPM_RC_P + TPM_RC_1)
#define RC_NV_DefineSpace_publicInfo (TPM_RC_P + TPM_RC_2)
#define RC_CreatePrimary_inPublic    (TPM_RC_P + TPM_RC_1)
#define RC_CreatePrimary_inSensitive (TPM_RC_P + TPM_RC_2)
#define RC_Create_parentHandle       (TPM_RC_H + TPM_RC_1)
#define RC_Create_inSensitive        (TPM_RC_P + TPM_RC_1)
#define RC_Create_inPublic           (TPM_RC_P + TPM_RC_2)
#define RC_Load_parentHandle         (TPM_RC_H + TPM_RC_1)
#define RC_Load_inPrivate            (TPM_RC_P + TPM_RC_1)
#define RC_Load_inPublic             (TPM_RC_P + TPM_RC_2)
/** @} */  /* TPM_RC modifiers */

/** @name TPM_ST — Structure tags */
/** @{ */
// TPM_ST
#define TPM_ST_NO_SESSIONS 0x8001
#define TPM_ST_SESSIONS    0x8002
#define TPM_ST_CREATION    0x8021
/** @} */  /* TPM_ST */

/** @name TPM_HANDLE — Well-known handles and NV index range */
/** @{ */
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
/** @} */  /* TPM_HANDLE */

/** @name Authorization pseudo-handles */
/** @{ */
// Authorization
#define TPM_RS_PW 0x40000009 /* Password authorization pseudo-handle */
/** @} */  /* Authorization */

/** @name TPM_CC — Command codes */
/** @{ */
// TPM_CC
#define TPM_CC_Startup           0x00000144
#define TPM_CC_Shutdown          0x00000145
#define TPM_CC_SelfTest          0x00000143
#define TPM_CC_GetCapability     0x0000017A
#define TPM_CC_GetTestResult     0x0000017C
#define TPM_CC_FieldUpgradeStart 0x0000012F
#define TPM_CC_FieldUpgradeData  0x00000141
#define TPM_CC_GetRandom         0x0000017B
/* NV Memory*/
#define TPM_CC_NV_DefineSpace 0x0000012A
#define TPM_CC_NV_Write       0x00000137
#define TPM_CC_NV_Read        0x0000014E
/* Cryptographic Primitives */
#define TPM_CC_Sign            0x0000015D
#define TPM_CC_VerifySignature 0x00000177
#define TPM_CC_Hash            0x0000017D
#define TPM_CC_EncryptDecrypt2 0x00000193
#define TPM_CC_RSA_Encrypt     0x00000174
#define TPM_CC_RSA_Decrypt     0x00000159
// TPM Key Life Cycle Management
#define TPM_CC_CreatePrimary 0x00000131
#define TPM_CC_Create        0x00000153
#define TPM_CC_Load          0x00000157
#define TPM_CC_ReadPublic    0x00000173
/** @} */  /* TPM_CC */

/** @name TPM_ALG_ID — Algorithm identifiers */
/** @{ */
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
/** @} */  /* TPM_ALG_ID */

/** @name Label / reset-default constants */
/** @{ */
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
/** @} */  /* Label / reset-default */
/** @} */  /* tpm2_constants §1 */

/* ====================================================================== */
/** @defgroup tpm2_macros §2 Macros
 *  Marshal/unmarshal helpers and attribute-access utilities.
 *  @{ */
/* ====================================================================== */

/** @name MARSHAL / UNMARSHAL — byte-stream serialisation via Fifo8 */
/** @{ */
#define UNMARSHAL(data, fifo) unmarshal(data, sizeof(*(data)), fifo)
#define MARSHAL(fifo, data)   marshal(fifo, data, sizeof(*(data)))
/** @} */  /* MARSHAL / UNMARSHAL */

/** @name Attribute-access helpers */
/** @{ */
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
/** @} */  /* Attribute-access helpers */
/** @} */  /* tpm2_macros §2 */

/* ====================================================================== */
/** @defgroup tpm2_basic_types §3 Basic Types
 *  Primitive typedefs, secondary typedefs, and specialisations.
 *  @{ */
/* ====================================================================== */

/** @name §3.1 Primitive Types */
/** @{ */

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
/** @} */  /* §3.1 */

/** @name §3.2 Secondary Types */
/** @{ */

/* Subsection #3.2: Secondary Types*/

typedef UINT8 TPM_HT;
typedef UINT16 TPM_SU;

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
typedef UINT32 TPM_PT;
typedef UINT32 TPM_CAP;

#define TPM_SU_CLEAR 0x0000
#define TPM_SU_STATE 0x0001

#define TPM_CAP_TPM_PROPERTIES 0x00000006

#define TPM_PT_FIXED         0x00000000
#define TPM_PT_VAR           0x00000100
#define TPM_PT_PERMANENT     (TPM_PT_VAR + 0)
#define TPM_PT_STARTUP_CLEAR (TPM_PT_VAR + 1)
#define TPM_PT_MODES         (TPM_PT_FIXED + 45)

#define TPMA_STARTUP_CLEAR_PH_ENABLE (1U << 0)
#define TPMA_STARTUP_CLEAR_SH_ENABLE (1U << 1)
#define TPMA_STARTUP_CLEAR_EH_ENABLE (1U << 2)
#define TPMA_STARTUP_CLEAR_READ_ONLY (1U << 4)
#define TPMA_STARTUP_CLEAR_ORDERLY   (1U << 31)

#define TPMA_PERMANENT_DISABLE_CLEAR (1U << 8)
#define TPMA_PERMANENT_IN_LOCKOUT    (1U << 9)

#define TPMA_MODES_FIPS_140_2 (1U << 0)
/** @} */  /* §3.2 */

/** @name §3.3 Specialisations of Secondary Types */
/** @{ */

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
/** @} */  /* §3.3 */
/** @} */  /* tpm2_basic_types §3 */

/* ====================================================================== */
/** @defgroup tpm2_complex_types §4 Complex Types
 *  Compound structures used in TPM commands and responses.
 *  @{ */
/* ====================================================================== */

/** @name §4.1 Hash and Digest Types */
/** @{ */

/** @brief Hash algorithm union — currently SHA-256 only. */
typedef union __packed {
    BYTE sha256[SHA256_DIGEST_SIZE]; /**< SHA-256 digest value (32 bytes). */
} TPMU_HA;

/** @brief Generic sized buffer (TPM 2.0 Part 2, Table 79). */
typedef struct __packed {
    UINT16 size;                 /**< Number of valid octets. */
    BYTE buffer[sizeof(TPMU_HA)]; /**< Data payload. */
} TPM2B;

/** @brief Sized buffer for generic data (TPM 2.0 Part 2, Table 87). */
typedef struct __packed {
    UINT16 size;                     /**< Octet count of valid data. */
    BYTE data[TPM_MAX_DATA_SIZE];    /**< Data payload (max 256 bytes). */
} TPM2B_DATA;

/** @brief Sized buffer for a signature blob (up to RSA-2048). */
typedef struct __packed {
    UINT16 size;                           /**< Signature length in octets. */
    BYTE buffer[TPM_MAX_SIGNATURE_SIZE];   /**< Raw signature bytes. */
} TPM2B_SIGNATURE;

/** @brief Sized buffer for a symmetric or asymmetric key. */
typedef struct __packed {
    UINT16 size;                      /**< Key length in octets. */
    BYTE buffer[TPM_MAX_KEY_SIZE];    /**< Raw key material. */
} TPM2B_KEY;

/** @brief Hash value with algorithm identifier (TCG Part 2, Table 80). */
typedef struct {
    TPMI_ALG_HASH hashAlg; /**< Algorithm of this digest. */
    TPMU_HA digest;        /**< Digest value. */
} TPMT_HA;

/** @brief Name union — either a digest or a handle. */
typedef union __packed {
    TPMT_HA digest;        /**< Digest-based name. */
    TPM_HANDLE handle;     /**< Handle-based name. */
} TPMU_NAME;

/** @brief Sized message digest (TPM 2.0 Part 2, Table 83). */
typedef struct __packed {
    UINT16 size;                   /**< Digest length in octets. */
    BYTE buffer[sizeof(TPMU_HA)];  /**< Digest payload. */
} TPM2B_DIGEST;

/** @brief Alias: authorisation value is a digest. */
typedef TPM2B_DIGEST TPM2B_AUTH;

/** @brief Sized Name buffer (for object or NV Names). */
typedef struct __packed {
    UINT16 size;                     /**< Name length in octets. */
    BYTE buffer[sizeof(TPMU_NAME)];  /**< Serialised Name. */
} TPM2B_NAME;
/** @} */  /* §4.1 */

/** @name §4.2 Signature and Ticket Types */
/** @{ */

/** @brief Signature scheme descriptor (algorithm + hash). */
typedef struct __packed {
    TPMI_ALG_SIG_SCHEME scheme;  /**< Signature algorithm (e.g. RSASSA, RSAPSS). */
    TPMI_ALG_HASH hashAlg;       /**< Hash algorithm to use with scheme. */
} TPMT_SIG_SCHEME;

/** @brief Hash-check validation ticket (TCG Part 2, Table 91). */
typedef struct __packed {
    TPM_ST tag;               /**< TPM_ST_HASHCHECK or TPM_ST_CREATION. */
    TPM_HANDLE hierarchy;     /**< Hierarchy that produced this ticket. */
    TPM2B_DIGEST digest;      /**< Ticket digest value. */
} TPMT_TK_HASHCHECK;

/** @brief Alias: verified ticket has the same layout. */
typedef TPMT_TK_HASHCHECK TPMT_TK_VERIFIED;

/** @brief Alias: creation ticket has the same layout. */
typedef TPMT_TK_HASHCHECK TPMT_TK_CREATION;

/** @brief Signature output structure (algorithm + hash + blob). */
typedef struct __packed {
    TPMI_ALG_SIG_SCHEME sigAlg;     /**< Signature algorithm used. */
    TPMI_ALG_HASH hashAlg;          /**< Hash algorithm used. */
    TPM2B_SIGNATURE signature;      /**< Raw signature data. */
} TPMT_SIGNATURE;
/** @} */  /* §4.2 */

/** @name §4.3 Symmetric Encryption Types */
/** @{ */

/** @brief Symmetric algorithm descriptor (algorithm + key size + mode). */
typedef struct __packed {
    TPMI_ALG_SYM_OBJECT algorithm; /**< Symmetric algorithm (e.g. TPM_ALG_AES). */
    TPMU_SYM_KEY_BITS keyBits;     /**< Key size in bits. */
    TPMU_SYM_MODE mode;            /**< Chaining mode (ECB, CBC, CFB, etc.). */
} TPMT_SYM_DEF_OBJECT;

/** @brief Sized IV buffer for symmetric encryption (AES block size). */
typedef struct __packed {
    UINT16 size;                       /**< IV length in octets. */
    BYTE buffer[TPM_MAX_IV_SIZE];      /**< IV data. */
} TPM2B_IV;

/** @brief Large sized buffer for symmetric operations. */
typedef struct __packed {
    UINT16 size;                              /**< Data length in octets. */
    BYTE buffer[TPM_MAX_MAX_BUFFER_SIZE];     /**< Data payload (up to 1024). */
} TPM2B_MAX_BUFFER;
/** @} */  /* §4.3 */

/** @name §4.4 Asymmetric (RSA) Types */
/** @{ */

/** @brief Sized RSA public key buffer (up to 2048-bit key). */
typedef struct __packed {
    UINT16 size;                       /**< Modulus length in octets. */
    BYTE buffer[TPM_MAX_KEY_SIZE];     /**< Raw modulus bytes. */
} TPM2B_PUBLIC_KEY_RSA;

/** @brief Sized RSA private key buffer (private exponent). */
typedef struct __packed {
    UINT16 size;                       /**< Private key length in octets. */
    BYTE buffer[RSA_PRIVATE_SIZE];     /**< Raw private key material. */
} TPM2B_PRIVATE_KEY_RSA;
/** @} */  /* §4.4 */

/** @name §4.5 PCR Types */
/** @{ */

/** @brief Single PCR bank selection (hash alg + bitmask). */
typedef struct __packed {
    TPMI_ALG_HASH hash;              /**< Hash algorithm for this bank. */
    UINT8 sizeofSelect;              /**< Number of octets in @c pcrSelect. */
    BYTE pcrSelect[PCR_SELECT_MAX];  /**< Bitmask of selected PCRs. */
} TPMS_PCR_SELECTION;

/** @brief List of PCR bank selections. */
typedef struct __packed {
    UINT32 count;                               /**< Number of selections. */
    TPMS_PCR_SELECTION pcrSelections[HASH_COUNT]; /**< Array of selections. */
} TPML_PCR_SELECTION;
/** @} */  /* §4.5 */

/** @name §4.6 NV Memory Types */
/** @{ */

/* Subsection #4.6: NV Memory Types */

/** Defines the end-of-list marker for NV. The list terminator is a UINT32 of
 * zero, followed by the current value of s_maxCounter which is a 64-bit value.
 * The structure is defined as an array of 3 UINT32 values so that there is no
 * padding between the  UINT32 list end marker and the UINT64 maxCounter */
typedef UINT32 NV_LIST_TERMINATOR[3];

typedef struct __packed {
    UINT16 size;
    BYTE buffer[MAX_NV_BUFFER_SIZE];
} TPM2B_MAX_NV_BUFFER;

/** @brief TPMA_NV — NV index attribute bitfield (TCG Part 2, Table 204). */
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

/** @brief TPMA_OBJECT — Object attribute bitfield (TCG Part 2, Table 31). */
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

/** @brief NV public area — index metadata (TCG Part 2, Table 207). */
typedef struct __packed {
    TPMI_RH_NV_LEGACY_INDEX nvIndex;  /**< NV index handle. */
    TPMI_ALG_HASH nameAlg;            /**< Hash algorithm for Name computation. */
    TPMA_NV attributes;               /**< Access and type attributes. */
    TPM2B_DIGEST authPolicy;          /**< Optional authorization policy digest. */
    UINT16 dataSize;                  /**< Maximum data size (≤ MAX_NV_INDEX_SIZE). */
} TPMS_NV_PUBLIC;

/** @brief Sized NV public area for marshalling. */
typedef struct __packed {
    UINT16 size;                 /**< Marshalled size of @c nvPublic. */
    TPMS_NV_PUBLIC nvPublic;     /**< NV index public metadata. */
} TPM2B_NV_PUBLIC;

/** @brief Internal NV index object (public + auth). */
typedef struct __packed {
    TPMS_NV_PUBLIC publicArea;   /**< Public metadata. */
    TPM2B_AUTH authValue;        /**< Authorization value for this index. */
} NV_INDEX;

/** @brief NV entry header for storage serialisation. */
typedef struct __packed {
    UINT32 size;            /**< Total entry size in bytes. */
    TPM_HANDLE handle;      /**< NV index handle. */
} NV_ENTRY_HEADER;
/** @} */  /* §4.6 */

/** @name §4.7 Key and Object Types */
/** @{ */

/** @brief Sized creation data buffer (opaque metadata blob). */
typedef struct __packed {
    UINT16 size;                            /**< Length of creation data. */
    BYTE buffer[TPM_MAX_MAX_BUFFER_SIZE];   /**< Serialised creation metadata. */
} TPM2B_CREATION_DATA;

/** @brief Sized label buffer (max 32 bytes). */
typedef struct __packed {
    UINT16 size;                     /**< Label length in octets. */
    BYTE buffer[LABEL_MAX_BUFFER];   /**< Label string data. */
} TPM2B_LABEL;

/** @brief Key derivation parameters (label + context). */
typedef struct __packed {
    TPM2B_LABEL label;     /**< Derivation label (e.g. "PRIMARY"). */
    TPM2B_LABEL context;   /**< Derivation context. */
} TPMS_DERIVE;

/** @brief Union for initial sensitive data (create vs. derive). */
typedef union __packed {
    BYTE create[MAX_SYM_DATA]; /**< User-supplied sensitive data. */
    TPMS_DERIVE derive;        /**< Derivation parameters. */
} TPMU_SENSITIVE_CREATE;

/** @brief Internal sized buffer for sensitive data. */
typedef struct __packed {
    UINT16 size;                                  /**< Data length. */
    BYTE buffer[sizeof(TPMU_SENSITIVE_CREATE)];    /**< Payload. */
} _TPM2B_SENSITIVE_DATA_BUFFER;

/** @brief Sized sensitive data buffer with dual-view access. */
typedef union __packed {
    _TPM2B_SENSITIVE_DATA_BUFFER t;  /**< Typed view. */
    _TPM2B_SENSITIVE_DATA_BUFFER b;  /**< Buffer view. */
    struct {
        UINT16 size;                                /**< Data length. */
        BYTE buffer[sizeof(TPMU_SENSITIVE_CREATE)];  /**< Payload. */
    };
} TPM2B_SENSITIVE_DATA;

/** @brief Sensitive creation parameters (auth + data). */
typedef struct __packed {
    TPM2B_AUTH userAuth;           /**< Initial authorization value. */
    TPM2B_SENSITIVE_DATA data;     /**< Initial sensitive data or derivation params. */
} TPMS_SENSITIVE_CREATE;

/** @brief Sized sensitive creation structure for marshalling. */
typedef struct __packed {
    UINT16 size;                         /**< Marshalled size. */
    TPMS_SENSITIVE_CREATE sensitive;      /**< Creation-sensitive content. */
} TPM2B_SENSITIVE_CREATE;

/** @brief Hash scheme details (single hash algorithm). */
typedef struct __packed {
    TPMI_ALG_HASH hashAlg;  /**< Hash algorithm for this scheme. */
} TPMS_SCHEME_HASH;

/** @brief Asymmetric scheme union (currently hash-only). */
typedef union __packed {
    TPMS_SCHEME_HASH anySig;  /**< Generic signing scheme details. */
} TPMU_ASYM_SCHEME;

/** @brief RSA scheme selector (scheme + hash details). */
typedef struct __packed {
    TPMI_ALG_RSA_SCHEME scheme;   /**< RSA scheme (RSASSA, RSAPSS, NULL). */
    TPMU_ASYM_SCHEME details;     /**< Scheme-specific parameters. */
} TPMT_RSA_SCHEME;

/** @brief RSA algorithm parameters (symmetric, scheme, key bits, exponent). */
typedef struct __packed {
    TPMT_SYM_DEF_OBJECT symmetric;  /**< Inner symmetric algorithm (for storage keys). */
    TPMT_RSA_SCHEME scheme;         /**< RSA signing/encryption scheme. */
    TPMI_RSA_KEY_BITS keyBits;      /**< Key size in bits (e.g. 2048). */
    UINT32 exponent;                /**< Public exponent (0 = default 65537). */
} TPMS_RSA_PARAMS;

/** @brief Public parameters union — keyed on TPMI_ALG_PUBLIC type. */
typedef struct __packed {
    TPMS_RSA_PARAMS rsaDetail;  /**< RSA-specific parameters. */
} TPMU_PUBLIC_PARAMS;

/** @brief Public unique data union — keyed on TPMI_ALG_PUBLIC type. */
typedef struct __packed {
    TPM2B_DIGEST keyedHash;        /**< Keyed-hash unique data. */
    TPM2B_DIGEST sym;              /**< Symmetric unique data. */
    TPM2B_PUBLIC_KEY_RSA rsa;      /**< RSA public modulus. */
    TPMS_DERIVE derive;            /**< Derivation values. */
} TPMU_PUBLIC_ID;

/** @brief Public area of a TPM object (TCG Part 2, Table 195). */
typedef struct __packed {
    TPMI_ALG_PUBLIC type;            /**< Algorithm type (TPM_ALG_RSA, etc.). */
    TPMI_ALG_HASH nameAlg;           /**< Hash algorithm for Name computation. */
    TPMA_OBJECT objectAttributes;    /**< Object attribute flags. */
    TPM2B_DIGEST authPolicy;         /**< Optional authorization policy. */
    TPMU_PUBLIC_PARAMS parameters;   /**< Algorithm-specific parameters. */
    TPMU_PUBLIC_ID unique;           /**< Unique identifier (public key). */
} TPMT_PUBLIC;

/** @brief Sized public area for wire marshalling. */
typedef struct __packed {
    UINT16 size;                /**< Marshalled size of publicArea. */
    TPMT_PUBLIC publicArea;     /**< The public area content. */
} TPM2B_PUBLIC;

/** @brief Sized seed buffer (hierarchy seed). */
typedef struct __packed {
    uint16_t size;             /**< Seed length in octets. */
    uint8_t buffer[64];        /**< Seed data. */
} TPM2B_SEED;

/** @brief Internal object attribute flags (QEMU device model). */
typedef struct __packed {
    unsigned publicOnly : 1;        /**< Object has no sensitive area. */
    unsigned epsHierarchy : 1;      /**< Belongs to Endorsement hierarchy. */
    unsigned ppsHierarchy : 1;      /**< Belongs to Platform hierarchy. */
    unsigned spsHierarchy : 1;      /**< Belongs to Storage (Owner) hierarchy. */
    unsigned evict : 1;             /**< Persistent (evict) object. */
    unsigned primary : 1;           /**< Primary object. */
    unsigned temporary : 1;         /**< Temporary object. */
    unsigned stClear : 1;           /**< Cleared on TPM2_Startup(CLEAR). */
    unsigned hmacSeq : 1;           /**< HMAC sequence object. */
    unsigned hashSeq : 1;           /**< Hash sequence object. */
    unsigned eventSeq : 1;          /**< Event sequence object. */
    unsigned ticketSafe : 1;        /**< Safe for ticket generation. */
    unsigned firstBlock : 1;        /**< First block flag (symmetric). */
    unsigned isParent : 1;          /**< Can be a parent for TPM2_Create. */
    unsigned not_used_14 : 1;       /**< Reserved. */
    unsigned occupied : 1;          /**< Slot is in use. */
    unsigned derivation : 1;        /**< Derived object. */
    unsigned external : 1;          /**< Externally loaded object. */
} OBJECT_ATTRIBUTES;

/** @brief Union of sensitive material keyed on algorithm type. */
typedef union __packed {
    TPM2B_PRIVATE_KEY_RSA rsa;  /**< RSA private exponent. */
} TPMU_SENSITIVE_COMPOSITE;

/** @brief Sensitive area of a TPM object (TCG Part 2, Table 201). */
typedef struct __packed {
    TPMI_ALG_PUBLIC sensitiveType;       /**< Algorithm type (must match public). */
    TPM2B_AUTH authValue;                /**< Object authorization value. */
    TPM2B_DIGEST seedValue;              /**< Seed for derived objects. */
    TPMU_SENSITIVE_COMPOSITE sensitive;   /**< Algorithm-specific private material. */
} TPMT_SENSITIVE;

/** @brief Internal sized buffer for private blob (encrypted sensitive). */
typedef struct __packed {
    UINT16 size;           /**< Blob length. */
    BYTE buffer[sizeof(TPMT_SENSITIVE) + SHA256_DIGEST_SIZE + 16]; /**< Payload. */
} _TPM2B_PRIVATE_BUFFER;

/** @brief Sized private blob with dual-view access. */
typedef union {
    _TPM2B_PRIVATE_BUFFER b;  /**< Buffer view. */
    struct {
        UINT16 size;          /**< Blob length. */
        BYTE buffer[sizeof(TPMT_SENSITIVE) + SHA256_DIGEST_SIZE + 16]; /**< Payload. */
    };
} TPM2B_PRIVATE;

/** @brief Complete TPM object (public + sensitive + metadata). */
typedef struct __packed {
    OBJECT_ATTRIBUTES attributes;    /**< Internal object flags. */
    TPMT_PUBLIC publicArea;          /**< Public area. */
    TPMT_SENSITIVE sensitive;        /**< Sensitive (private) area. */
    TPM2B_NAME qualifiedName;        /**< Qualified Name (full hierarchy chain). */
    TPMI_DH_OBJECT evictHandle;      /**< Persistent handle (0 if transient). */
    TPM2B_NAME name;                 /**< Name: nameAlg || Hash(TPMT_PUBLIC). */
    TPMI_RH_HIERARCHY hierarchy;     /**< Owning hierarchy handle. */
} OBJECT;
/** @} */  /* §4.7 */

/** @name §4.8 Authorization Types */
/** @{ */

/**
 * @brief Authorization area in a command (after parameters).
 *
 * Used with TPM_ST_SESSIONS commands for password-based
 * authorisation.  Reference: TPM 2.0 Part 1, Table 75.
 */
typedef struct __packed {
    UINT32 sessionHandle;    /**< Session handle (TPM_RS_PW for password). */
    TPM2B_DIGEST nonce;      /**< Caller nonce (empty for password auth). */
    BYTE sessionAttributes;  /**< Session attribute flags. */
    TPM2B_AUTH hmac;          /**< Password or HMAC value. */
} TPMS_AUTH_COMMAND;

/**
 * @brief Authorization area in a response (after parameters).
 *
 * Reference: TPM 2.0 Part 1, Table 76.
 */
typedef struct __packed {
    TPM2B_DIGEST nonce;      /**< TPM nonce (empty for password auth). */
    BYTE sessionAttributes;  /**< Session attribute flags. */
    TPM2B_AUTH hmac;          /**< Response HMAC (empty for password auth). */
} TPMS_AUTH_RESPONSE;

/** @brief Wire-format command auth area (size prefix + content). */
typedef struct __packed {
    UINT32 authSize;              /**< Size of the following auth structure. */
    TPMS_AUTH_COMMAND auth;       /**< Authorization content. */
} TPMS_AUTH_COMMAND_AREA;

/** @brief Wire-format response auth area (size prefix + content). */
typedef struct __packed {
    UINT32 authSize;              /**< Size of the following auth structure. */
    TPMS_AUTH_RESPONSE auth;      /**< Authorization response content. */
} TPMS_AUTH_RESPONSE_AREA;
/** @} */  /* §4.8 */

/** @name §4.9 DRBG (Random Number Generator) Types */
/** @{ */

/** @brief DRBG symmetric key (AES-256). */
typedef union {
    BYTE bytes[DRBG_KEY_SIZE_BYTES];        /**< Byte-level access. */
    crypt_uword_t words[DRBG_KEY_SIZE_WORDS]; /**< Word-level access. */
} DRBG_KEY;

/** @brief DRBG initialisation vector (128-bit AES block). */
typedef union {
    BYTE bytes[DRBG_IV_SIZE_BYTES];        /**< Byte-level access. */
    crypt_uword_t words[DRBG_IV_SIZE_WORDS]; /**< Word-level access. */
} DRBG_IV;

/** @brief DRBG seed material. */
typedef union {
    BYTE bytes[DRBG_SEED_SIZE_BYTES];        /**< Byte-level access. */
    crypt_uword_t words[DRBG_SEED_SIZE_WORDS]; /**< Word-level access. */
} DRBG_SEED;

/** @brief DRBG internal state (CTR_DRBG). */
typedef struct __packed {
    UINT64 reseedCounter;   /**< Reseed counter. */
    UINT32 magic;           /**< Magic number for validity check. */
    DRBG_SEED seed;         /**< Current seed value. */
    UINT32 lastValue[4];    /**< Last generated block. */
} DRBG_STATE;

/** @brief Alias: random state is a DRBG state. */
typedef DRBG_STATE RAND_STATE;
/** @} */  /* §4.9 */

/** @name §4.10 Command and Response Headers */
/** @{ */

/* Subsection #4.10: Command and Response Headers */

/** @brief Command header sent by firmware to the TPM (§3.1 Transport). */
// Command Header
typedef struct __packed {
    TPMI_ST_COMMAND_TAG tag;
    UINT32 commandSize;
    TPM_CC commandCode;
} tpm_cmd_header_t;

/** @brief Response header received from the TPM (§3.1 Transport). */
// Response Header
typedef struct __packed {
    TPM_ST tag;
    UINT32 responseSize;
    TPM_RC responseCode;
} tpm_rsp_header_t;
/** @} */  /* §4.10 */

/** @name §4.11 TPM State Data */
/** @{ */

/* Subsection #4.11: TPM State Data */

/** @brief Persistent state surviving TPM2_Shutdown(STATE) / Startup(STATE). */
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
/** @} */  /* §4.11 */
/** @} */  /* tpm2_complex_types §4 */

/* ====================================================================== */
/** @defgroup tpm2_cmd_io §5 Command I/O Structures
 *  Per-command input and output structures for marshal/unmarshal.
 *  @{ */
/* ====================================================================== */

/** @name §5.1 Random Number Generation & State Machine Commands */
/** @{ */

/** @brief Input for TPM2_Startup. */
typedef struct __packed {
    TPM_SU startupType;  /**< TPM_SU_CLEAR or TPM_SU_STATE. */
} Startup_In;

/** @brief Input for TPM2_Shutdown. */
typedef struct __packed {
    TPM_SU shutdownType;  /**< TPM_SU_CLEAR or TPM_SU_STATE. */
} Shutdown_In;

/** @brief Input for TPM2_SelfTest. */
typedef struct __packed {
    TPMI_YES_NO fullTest;  /**< YES for full test, NO for incremental. */
} SelfTest_In;

/** @brief Input for TPM2_GetCapability. */
typedef struct __packed {
    TPM_CAP capability;     /**< Category of capability (e.g. TPM_CAP_TPM_PROPERTIES). */
    TPM_PT property;        /**< Starting property tag. */
    UINT32 propertyCount;   /**< Maximum number of properties to return. */
} GetCapability_In;

/** @brief Output for TPM2_GetCapability (single property). */
typedef struct __packed {
    TPMI_YES_NO moreData;  /**< YES if more data is available. */
    TPM_PT property;       /**< Property tag returned. */
    UINT32 value;          /**< Property value. */
} GetCapability_Out;

/** @brief Output for TPM2_GetTestResult. */
typedef struct __packed {
    TPM2B_MAX_BUFFER outData;  /**< Test result data. */
    TPM_RC testResult;         /**< Test result code. */
} GetTestResult_Out;

/** @brief Input for TPM2_FieldUpgradeData. */
typedef struct __packed {
    TPM2B_MAX_BUFFER fuData;  /**< Firmware upgrade data block. */
} FieldUpgradeData_In;

/** @brief Input for TPM2_GetRandom. */
typedef struct __packed {
    UINT16 bytesRequested;  /**< Number of random octets to generate. */
} GetRandom_In;

/** @brief Output for TPM2_GetRandom. */
typedef struct __packed {
    TPM2B_DIGEST randomBytes;  /**< Generated random data. */
} GetRandom_Out;
/** @} */  /* §5.1 */

/** @name §5.2 NV Memory Commands */
/** @{ */

/** @brief Input for TPM2_NV_DefineSpace. */
typedef struct __packed {
    TPMI_RH_PROVISION authHandle; /**< Authorising handle (Owner/Platform). */
    TPM2B_AUTH auth;              /**< Authorization value for the new index. */
    TPM2B_NV_PUBLIC publicInfo;   /**< NV index public metadata. */
} NV_DefineSpace_In;

/** @brief Input for TPM2_NV_Write. */
typedef struct __packed {
    TPMI_RH_NV_AUTH authHandle;    /**< Authorization handle. */
    TPMI_RH_NV_INDEX nvIndex;      /**< NV index to write. */
    TPM2B_MAX_NV_BUFFER data;      /**< Data to write. */
    UINT16 offset;                 /**< Byte offset within the NV index. */
} NV_Write_In;

/** @brief Input for TPM2_NV_Read. */
typedef struct __packed {
    TPMI_RH_NV_AUTH authHandle;    /**< Authorization handle. */
    TPMI_RH_NV_INDEX nvIndex;      /**< NV index to read. */
    UINT16 size;                   /**< Number of octets to read. */
    UINT16 offset;                 /**< Byte offset within the NV index. */
} NV_Read_In;

/** @brief Output for TPM2_NV_Read. */
typedef struct __packed {
    TPM2B_MAX_NV_BUFFER data;      /**< Data read from NV. */
} NV_Read_Out;
/** @} */  /* §5.2 */

/** @name §5.3 Cryptographic Commands */
/** @{ */

/** @brief Input for TPM2_Sign (TPM 2.0 Part 3, Table 109). */
typedef struct __packed {
    TPM_HANDLE keyHandle;            /**< Handle of the signing key. */
    TPMT_SIG_SCHEME inScheme;        /**< Signing scheme selector. */
    TPM2B_DIGEST digest;             /**< Digest to be signed. */
    TPMT_TK_HASHCHECK validation;    /**< Optional hash-check ticket. */
} Sign_In;

/** @brief Output for TPM2_Sign. */
typedef struct __packed {
    TPMT_SIGNATURE signature;        /**< Resulting signature. */
} Sign_Out;

/** @brief Input for TPM2_VerifySignature. */
typedef struct __packed {
    TPM_HANDLE keyHandle;            /**< Handle of the verification key. */
    TPM2B_DIGEST digest;             /**< Digest that was signed. */
    TPMT_SIGNATURE signature;        /**< Signature to verify. */
} VerifySignature_In;

/** @brief Output for TPM2_VerifySignature. */
typedef struct __packed {
    TPMT_TK_VERIFIED validation;     /**< Validation ticket on success. */
} VerifySignature_Out;

/** @brief Input for TPM2_Hash. */
typedef struct __packed {
    TPM2B_MAX_BUFFER data;           /**< Data to hash. */
    TPMI_ALG_HASH hashAlg;           /**< Hash algorithm to use. */
    TPMI_RH_HIERARCHY hierarchy;     /**< Hierarchy for the ticket. */
} Hash_In;

/** @brief Output for TPM2_Hash. */
typedef struct __packed {
    TPM2B_DIGEST digest;             /**< Resulting digest. */
    TPMT_TK_HASHCHECK validation;    /**< Hash-check ticket. */
} Hash_Out;

/** @brief Input for TPM2_EncryptDecrypt2. */
typedef struct __packed {
    TPMI_DH_OBJECT keyHandle;        /**< Symmetric key handle. */
    TPMI_YES_NO decrypt;             /**< NO = encrypt, YES = decrypt. */
    TPMI_ALG_CIPHER_MODE mode;       /**< Cipher mode (ECB, CBC, CFB, etc.). */
    TPM2B_IV ivIn;                   /**< Input initialisation vector. */
    TPM2B_MAX_BUFFER inData;         /**< Plaintext or ciphertext. */
} EncryptDecrypt2_In;

/** @brief Output for TPM2_EncryptDecrypt2. */
typedef struct __packed {
    TPM2B_MAX_BUFFER outData;        /**< Encrypted or decrypted result. */
    TPM2B_IV ivOut;                  /**< Output IV (for chaining). */
} EncryptDecrypt2_Out;

/** @brief Input for TPM2_RSA_Encrypt. */
typedef struct __packed {
    TPM_HANDLE keyHandle;            /**< Public key handle. */
    TPM2B_PUBLIC_KEY_RSA message;    /**< Plaintext message. */
} RSA_Encrypt_In;

/** @brief Output for TPM2_RSA_Encrypt. */
typedef struct __packed {
    TPM2B_PUBLIC_KEY_RSA encrypted;  /**< Ciphertext. */
} RSA_Encrypt_Out;

/** @brief Input for TPM2_RSA_Decrypt. */
typedef struct __packed {
    TPM_HANDLE keyHandle;            /**< Private key handle. */
    TPM2B_PUBLIC_KEY_RSA encrypted;  /**< Ciphertext to decrypt. */
} RSA_Decrypt_In;

/** @brief Output for TPM2_RSA_Decrypt. */
typedef struct __packed {
    TPM2B_PUBLIC_KEY_RSA decrypted;  /**< Recovered plaintext. */
} RSA_Decrypt_Out;
/** @} */  /* §5.3 */

/** @name §5.4 Key Lifecycle Management Commands */
/** @{ */

/** @brief Input for TPM2_CreatePrimary (TPM 2.0 Part 3, Table 174). */
typedef struct __packed {
    TPMI_RH_HIERARCHY primaryHandle;    /**< Hierarchy (Owner/Endorsement/Platform). */
    TPM2B_SENSITIVE_CREATE inSensitive; /**< Initial sensitive data. */
    TPM2B_PUBLIC inPublic;              /**< Public template. */
    TPM2B_DATA outsideInfo;             /**< External linkage data. */
    TPML_PCR_SELECTION creationPCR;     /**< PCR selection for creation data. */
} CreatePrimary_In;

/** @brief Output for TPM2_CreatePrimary (TPM 2.0 Part 3, Table 175). */
typedef struct __packed {
    TPM_HANDLE objectHandle;            /**< Transient handle of the new primary. */
    TPM2B_PUBLIC outPublic;             /**< Public area of the created object. */
    TPM2B_CREATION_DATA creationData;   /**< Creation metadata. */
    TPM2B_DIGEST creationHash;          /**< Hash of creationData. */
    TPMT_TK_CREATION creationTicket;    /**< Validation ticket. */
    TPM2B_NAME name;                    /**< Name of the created object. */
} CreatePrimary_Out;

/** @brief Input for TPM2_Create (TPM 2.0 Part 3, Table 18). */
typedef struct __packed {
    TPMI_DH_OBJECT parentHandle;        /**< Loaded parent key handle. */
    TPM2B_SENSITIVE_CREATE inSensitive; /**< Initial sensitive data. */
    TPM2B_PUBLIC inPublic;              /**< Public template. */
    TPM2B_DATA outsideInfo;             /**< External linkage data. */
    TPML_PCR_SELECTION creationPCR;     /**< PCR selection for creation data. */
} Create_In;

/** @brief Output for TPM2_Create (TPM 2.0 Part 3, Table 19). */
typedef struct __packed {
    TPM2B_PRIVATE outPrivate;           /**< Encrypted private portion. */
    TPM2B_PUBLIC outPublic;             /**< Public area. */
    TPM2B_CREATION_DATA creationData;   /**< Creation metadata. */
    TPM2B_DIGEST creationHash;          /**< Hash of creationData. */
    TPMT_TK_CREATION creationTicket;    /**< Validation ticket. */
} Create_Out;

/** @brief Input for TPM2_Load (TPM 2.0 Part 3, Table 20). */
typedef struct __packed {
    TPMI_DH_OBJECT parentHandle;  /**< Parent key handle. */
    TPM2B_PRIVATE inPrivate;      /**< Private portion (from TPM2_Create). */
    TPM2B_PUBLIC inPublic;        /**< Public portion (from TPM2_Create). */
} Load_In;

/** @brief Output for TPM2_Load (TPM 2.0 Part 3, Table 21). */
typedef struct __packed {
    TPM_HANDLE objectHandle;      /**< Transient handle (0x80xxxxxx). */
    TPM2B_NAME name;              /**< Name of the loaded object. */
} Load_Out;

/** @brief Input for TPM2_ReadPublic (TPM 2.0 Part 3, Table 24). */
typedef struct __packed {
    TPMI_DH_OBJECT objectHandle;  /**< Handle of the loaded object. */
} ReadPublic_In;

/** @brief Output for TPM2_ReadPublic (TPM 2.0 Part 3, Table 25). */
typedef struct __packed {
    TPM2B_PUBLIC outPublic;       /**< Public area of the object. */
    TPM2B_NAME name;              /**< Object Name. */
    TPM2B_NAME qualifiedName;     /**< Qualified Name (hierarchy chain). */
} ReadPublic_Out;
/** @} */  /* §5.4 */
/** @} */  /* tpm2_cmd_io §5 */

/* ====================================================================== */
/** @defgroup tpm2_prototypes §6 Function Prototypes
 *  Entry points used by the QEMU device model and firmware test harness.
 *  @{ */
/* ====================================================================== */

/** @name §6.1 Marshalling and Unmarshalling */
/** @{ */

/**
 * @brief Unmarshal (deserialise) @p size bytes from FIFO into @p data.
 *
 * @param[out] data  Destination buffer.
 * @param[in]  size  Number of bytes to read.
 * @param[in]  fifo  Source FIFO.
 */
void unmarshal(void *data, size_t size, Fifo8 *fifo);

/**
 * @brief Marshal (serialise) @p size bytes from @p data into FIFO.
 *
 * @param[in] fifo  Destination FIFO.
 * @param[in] data  Source buffer.
 * @param[in] size  Number of bytes to write.
 */
void marshal(Fifo8 *fifo, const void *data, size_t size);
/** @} */  /* §6.1 */

/** @name §6.2 NV Helper Functions */
/** @{ */

/**
 * @brief Look up an NV index by handle.
 *
 * @param[in]  nvHandle  NV index handle to search for.
 * @param[out] locator   Receives the internal NV reference (may be NULL).
 * @return Pointer to the NV_INDEX if found; NULL otherwise.
 */
NV_INDEX *NvGetIndexInfo(TPM_HANDLE nvHandle, NV_REF *locator);

/**
 * @brief Check write-access permissions for an NV index.
 *
 * @param authHandle  Authorization handle.
 * @param nvHandle    Target NV index.
 * @param attributes  NV index attributes.
 * @return TPM_RC_SUCCESS if permitted; error code otherwise.
 */
TPM_RC NvWriteAccessChecks(TPM_HANDLE authHandle, TPM_HANDLE nvHandle,
                           TPMA_NV attributes);

/**
 * @brief Write data to an NV index.
 *
 * @param nvIndex  NV index object.
 * @param offset   Byte offset within the index.
 * @param size     Number of bytes to write.
 * @param data     Source data.
 * @return TPM_RC_SUCCESS on success; error code otherwise.
 */
TPM_RC NvWriteIndexData(NV_INDEX *nvIndex, UINT32 offset, UINT32 size,
                        void *data);

/**
 * @brief Check read-access permissions for an NV index.
 *
 * @param authHandle  Authorization handle.
 * @param nvHandle    Target NV index.
 * @param attributes  NV index attributes.
 * @return TPM_RC_SUCCESS if permitted; error code otherwise.
 */
TPM_RC NvReadAccessChecks(TPM_HANDLE authHandle, TPM_HANDLE nvHandle,
                          TPMA_NV attributes);

/**
 * @brief Read data from an NV index.
 *
 * @param nvIndex  NV index object.
 * @param locator  Internal NV reference.
 * @param offset   Byte offset.
 * @param size     Number of octets to read.
 * @param data     Destination buffer.
 */
void NvGetIndexData(NV_INDEX *nvIndex, NV_REF locator, UINT32 offset,
                    UINT16 size, void *data);

/**
 * @brief Define a new NV index with full validation.
 *
 * @param authHandle       Authorisation handle.
 * @param auth             Auth value for the new index.
 * @param publicInfo       NV public metadata.
 * @param blameAuthHandle  Error modifier for authHandle.
 * @param blameAuth        Error modifier for auth.
 * @param blamePublic      Error modifier for publicInfo.
 * @return TPM_RC_SUCCESS on success; error code otherwise.
 */
TPM_RC NvDefineSpace(TPMI_RH_PROVISION authHandle, TPM2B_AUTH *auth,
                     TPMS_NV_PUBLIC *publicInfo, TPM_RC blameAuthHandle,
                     TPM_RC blameAuth, TPM_RC blamePublic);

/**
 * @brief Initialise the volatile NV storage subsystem.
 *
 * @param memory          Backing memory for NV data.
 * @param size            Size of the backing memory in bytes.
 * @param tpm_saved_state Pointer to TPM saved state (for reset).
 * @return TRUE on success; FALSE on failure.
 */
BOOL NvInit(void *memory, size_t size, state_clear_data *tpm_saved_state);
/** @} */  /* §6.2 */

/** @name State Machine Helpers\n *  Functions implemented in @ref tpm_state_machine.c.\n *  @{ */\nstruct S32k358TPMState;\n\n/** @brief Reset all state-machine flags to power-on defaults. */\nvoid tpm_state_machine_reset(struct S32k358TPMState *s);\n\n/**\n * @brief Check whether @p cc is allowed in the current TPM mode.\n * @param[out] rc_out  Receives the rejection code on failure.\n * @return @c true if the command may proceed.\n */\nbool tpm_command_allowed_in_current_mode(struct S32k358TPMState *s, TPM_CC cc,\n                                         TPM_RC *rc_out);\n\n/** @brief State-machine Startup handler. */\nTPM_RC TPM2_Startup_SM(struct S32k358TPMState *s, Startup_In *in);\n/** @brief State-machine Shutdown handler. */\nTPM_RC TPM2_Shutdown_SM(struct S32k358TPMState *s, Shutdown_In *in);\n/** @brief State-machine SelfTest handler. */\nTPM_RC TPM2_SelfTest_SM(struct S32k358TPMState *s, SelfTest_In *in);\n/** @brief State-machine GetTestResult handler. */\nTPM_RC TPM2_GetTestResult_SM(struct S32k358TPMState *s, GetTestResult_Out *out);\n/** @brief State-machine GetCapability handler. */\nTPM_RC TPM2_GetCapability_SM(struct S32k358TPMState *s, GetCapability_In *in,\n                             GetCapability_Out *out);\n/** @brief State-machine FieldUpgradeStart handler. */\nTPM_RC TPM2_FieldUpgradeStart_SM(struct S32k358TPMState *s);\n/** @brief State-machine FieldUpgradeData handler. */\nTPM_RC TPM2_FieldUpgradeData_SM(struct S32k358TPMState *s,\n                                FieldUpgradeData_In *in);\n/** @} */

/** @name §6.3 TPM Command Entry Points */
/** @{ */

/** @brief Generate random bytes. */
TPM_RC TPM2_GetRandom(GetRandom_In *in, GetRandom_Out *out);

/** @brief Sign a digest with a loaded key. */
TPM_RC TPM2_Sign(Sign_In *in, Sign_Out *out);

/** @brief Verify a signature against a public key. */
TPM_RC TPM2_VerifySignature(VerifySignature_In *in, VerifySignature_Out *out);

/** @brief Compute a hash of the supplied data. */
TPM_RC TPM2_Hash(Hash_In *in, Hash_Out *out);

/** @brief Symmetric encrypt or decrypt. */
TPM_RC TPM2_EncryptDecrypt2(EncryptDecrypt2_In *in, EncryptDecrypt2_Out *out);

/** @brief RSA-OAEP encrypt. */
TPM_RC TPM2_RSA_Encrypt(RSA_Encrypt_In *in, RSA_Encrypt_Out *out);

/** @brief RSA-OAEP decrypt. */
TPM_RC TPM2_RSA_Decrypt(RSA_Decrypt_In *in, RSA_Decrypt_Out *out);

/** @brief Create a primary key under a hierarchy. */
TPM_RC TPM2_CreatePrimary(CreatePrimary_In *in, CreatePrimary_Out *out);

/** @brief Create a child key object (not loaded). */
TPM_RC TPM2_Create(Create_In *in, Create_Out *out);

/** @brief Load a key created by TPM2_Create. */
TPM_RC TPM2_Load(Load_In *in, Load_Out *out);

/** @brief Read the public area of a loaded object. */
TPM_RC TPM2_ReadPublic(ReadPublic_In *in, ReadPublic_Out *out);

/** @brief Define a new NV index. */
TPM_RC TPM2_NV_DefineSpace(NV_DefineSpace_In *in);

/** @brief Write data to an NV index. */
TPM_RC TPM2_NV_Write(NV_Write_In *in);

/** @brief Read data from an NV index. */
TPM_RC TPM2_NV_Read(NV_Read_In *in, NV_Read_Out *out);
/** @} */  /* §6.3 */
/** @} */  /* tpm2_prototypes §6 */

#endif /* TPM2_SPEC_PROTOCOL_H */
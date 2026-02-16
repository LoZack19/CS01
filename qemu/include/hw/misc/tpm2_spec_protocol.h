/**
 * @file   tpm2_spec_protocol.h
 * @brief  TPM 2.0 protocol constants, types, and wire structures.
 *
 * This is the canonical source; the firmware copy at
 * @c firmware/include/tpm2_spec_protocol.h is generated during the
 * build.  All edits must be made here.
 *
 * The file is organised into six sections matching the TPM 2.0
 * specification:
 *  -# Constants (return codes, algorithm IDs, handle ranges, …)
 *  -# Macros   (attribute tests, marshaling helpers)
 *  -# Basic Types (integral typedefs)
 *  -# Complex Types (structures, unions, TPM2B buffers)
 *  -# Command I/O structures (packed request/response headers)
 *  -# Function prototypes (command dispatcher, NV, driver)
 *
 * @see TPM 2.0 Part 2 – Structures
 */
#ifndef TPM2_SPEC_PROTOCOL_H
#define TPM2_SPEC_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include "include/qemu/fifo8.h"

#define __packed __attribute__((packed))

/** @name Section 1 – Constants
 *  @{ */

// Size Configuration
/* Cryptographic Primitives */
#define SHA256_DIGEST_SIZE      32
#define TPM_MAX_KEY_SIZE        256
#define TPM_MAX_DATA_SIZE       256
#define TPM_MAX_SIGNATURE_SIZE  256
#define TPM_MAX_IV_SIZE         16   /* TPM2B_IV uses AES block length */
#define TPM_MAX_MAX_BUFFER_SIZE 1024 /* Implementation-defined max buffer */
#define RSA_PRIVATE_SIZE        256  /* Supports up to RSA-2048 keys */
#define MAX_PRIVATE_SIZE        (sizeof(TPMT_SENSITIVE) + SHA256_DIGEST_SIZE + 16)
/* DRBG (Deterministic Random Bit Generator) */
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

/** @defgroup NVIndexTypes NV Index Types
 *  @brief TPM_NT values indicating the type of NV index.
 *  @{ */
#define TPM_NT_ORDINARY 0x0  /**< Ordinary data index (read/write) */
#define TPM_NT_COUNTER  0x1  /**< Monotonic counter index */
#define TPM_NT_BITS     0x2  /**< Bit field index */
#define TPM_NT_EXTEND   0x4  /**< Extend-only index (like PCR) */
#define TPM_NT_PIN_FAIL 0x8  /**< PIN fail counter */
#define TPM_NT_PIN_PASS 0x9  /**< PIN pass counter */
/** @} */

/** @defgroup ResponseCodes TPM Response Codes (TPM_RC)
 *  @brief Return values indicating command success or specific failure modes.
 *  @note These are defined in TPM 2.0 Part 2, Section 6.6.
 *  @{ */
#define TPM_RC_SUCCESS          (TPM_RC)0x000  /**< Command completed successfully */
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
#define TPM_RC_BINDING          (TPM_RC)(RC_FMT1 + 0x022)  /**< Key and public not cryptographically bound */
#define TPM_RCS_BINDING         (TPM_RC)(RC_FMT1 + 0x022)  /**< Alias for TPM_RC_BINDING */
#define TPM_RC_SEQUENCE         (TPM_RC)(RC_FMT1 + 0x023)  /**< Improper use of sequence handle */
/** @} */

/** @defgroup ResponseCodeModifiers Command-Specific Response Code Modifiers
 *  @brief Pre-computed RC values identifying specific parameters/handles in commands.
 *  @{ */
#define RC_NV_DefineSpace_authHandle (TPM_RC_H + TPM_RC_1)
#define RC_NV_DefineSpace_auth       (TPM_RC_P + TPM_RC_1)
#define RC_NV_DefineSpace_publicInfo (TPM_RC_P + TPM_RC_2)
#define RC_CreatePrimary_inPublic    (TPM_RC_P + TPM_RC_1)
#define RC_CreatePrimary_inSensitive (TPM_RC_P + TPM_RC_2)
#define RC_Create_parentHandle       (TPM_RC_H + TPM_RC_1)
#define RC_Create_inSensitive        (TPM_RC_P + TPM_RC_1)
#define RC_Create_inPublic           (TPM_RC_P + TPM_RC_2)
#define RC_Load_parentHandle         (TPM_RC_H + TPM_RC_1)  /**< Error in Load parentHandle */
#define RC_Load_inPrivate            (TPM_RC_P + TPM_RC_1)  /**< Error in Load inPrivate */
#define RC_Load_inPublic             (TPM_RC_P + TPM_RC_2)  /**< Error in Load inPublic */
/** @} */

/** @defgroup StructureTags Structure Tags (TPM_ST)
 *  @brief Tags used to disambiguate structure types in command/response headers.
 *  @note See TPM 2.0 Part 2, Section 6.3.
 *  @{ */
#define TPM_ST_NO_SESSIONS 0x8001  /**< Command/Response with no authorization sessions */
#define TPM_ST_SESSIONS    0x8002  /**< Command/Response with authorization sessions */
#define TPM_ST_CREATION    0x8021  /**< Tag for Creation Ticket (TPMT_TK_CREATION) */
/** @} */

/** @defgroup Handles TPM Handles
 *  @brief 32-bit identifiers for TPM entities (hierarchies, objects, NV indices).
 *  @note See TPM 2.0 Part 2, Section 7.
 *  @{ */
#define TPM_RH_OWNER                0x40000001  /**< Storage hierarchy (Owner) */
#define TPM_RH_NULL                 0x40000007  /**< Null hierarchy */
#define TPM_RH_UNASSIGNED           0x40000008  /**< Unassigned handle */
#define TPM_RH_ENDORSEMENT          0x4000000B  /**< Endorsement hierarchy */
#define TPM_RH_PLATFORM             0x4000000C  /**< Platform hierarchy */
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
#define NV_INDEX_FIRST              (HR_NV_INDEX + 0)       /**< First NV index handle */
#define NV_INDEX_LAST               (NV_INDEX_FIRST + 0x00FFFFFF)  /**< Last NV index handle */
/** @} */

/** @defgroup Authorization Authorization Constants
 *  @{ */
#define TPM_RS_PW 0x40000009  /**< Password authorization pseudo-handle (for HMAC sessions) */
/** @} */

/** @defgroup CommandCodes TPM Command Codes (TPM_CC)
 *  @brief Identifiers for TPM 2.0 commands.
 *  @note See TPM 2.0 Part 2, Section 6.5.
 *  @{ */
#define TPM_CC_Startup           0x00000144  /**< Initialize TPM state (CLEAR or STATE) */
#define TPM_CC_Shutdown          0x00000145  /**< Prepare TPM for power down */
#define TPM_CC_SelfTest          0x00000143  /**< Perform TPM self-test */
#define TPM_CC_GetCapability     0x0000017A  /**< Query TPM capabilities */
#define TPM_CC_GetTestResult     0x0000017C  /**< Get self-test results */
#define TPM_CC_FieldUpgradeStart 0x0000012F  /**< Start firmware upgrade */
#define TPM_CC_FieldUpgradeData  0x00000141  /**< Send firmware upgrade data */
#define TPM_CC_GetRandom         0x0000017B  /**< Generate random bytes */
/* NV Memory Commands */
#define TPM_CC_NV_DefineSpace 0x0000012A  /**< Define a new NV index */
#define TPM_CC_NV_Write       0x00000137  /**< Write data to NV index */
#define TPM_CC_NV_Read        0x0000014E  /**< Read data from NV index */
/* Cryptographic Primitives */
#define TPM_CC_Sign            0x0000015D  /**< Sign a digest using a loaded key */
#define TPM_CC_VerifySignature 0x00000177  /**< Verify a signature */
#define TPM_CC_Hash            0x0000017D  /**< Compute hash of data */
#define TPM_CC_EncryptDecrypt2 0x00000193  /**< Symmetric encrypt/decrypt */
#define TPM_CC_RSA_Encrypt     0x00000174  /**< RSA encryption */
#define TPM_CC_RSA_Decrypt     0x00000159  /**< RSA decryption */
/* Key Lifecycle Management Commands */
#define TPM_CC_CreatePrimary 0x00000131  /**< Create primary key from hierarchy seed */
#define TPM_CC_Create        0x00000153  /**< Create child key (returns encrypted blob) */
#define TPM_CC_Load          0x00000157  /**< Load key into transient object slot */
#define TPM_CC_ReadPublic    0x00000173  /**< Read public area of loaded object */
/** @} */

/** @defgroup AlgorithmIDs Algorithm Identifiers (TPM_ALG_ID)
 *  @brief Identifiers for cryptographic algorithms.
 *  @note See TPM 2.0 Part 2, Section 6.3.
 *  @{ */
#define TPM_ALG_RSA      0x0001  /**< RSA asymmetric algorithm */
#define TPM_ALG_TDES     0x0003  /**< Triple DES symmetric algorithm */
#define TPM_ALG_SHA1     0x0004  /**< SHA-1 hash algorithm */
#define TPM_ALG_AES      0x0006  /**< AES symmetric algorithm */
#define TPM_ALG_SHA256   0x000B  /**< SHA-256 hash algorithm */
#define TPM_ALG_NULL     0x0010  /**< Null algorithm (unspecified/default) */
#define TPM_ALG_SM4      0x0013  /**< SM4 symmetric algorithm */
#define TPM_ALG_RSASSA   0x0014  /**< RSA signature scheme (PKCS#1 v1.5) */
#define TPM_ALG_CAMELLIA 0x0015  /**< Camellia symmetric algorithm */
#define TPM_ALG_RSAPSS   0x0016  /**< RSA signature scheme (PSS) */
#define TPM_ALG_CTR      0x0040  /**< Counter mode (block cipher) */
#define TPM_ALG_XTS      0x0041  /**< XTS mode (block cipher) */
#define TPM_ALG_CBC      0x0042  /**< Cipher Block Chaining mode */
#define TPM_ALG_CFB      0x0043  /**< Cipher Feedback mode */
#define TPM_ALG_ECB      0x0044  /**< Electronic Codebook mode */
#define TPM_ALG_OFB      0x0045  /**< Output Feedback mode */
/** @} */

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

/** @} */

/** @name Section 2 – Macros
 *  @{ */

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

/** @} */

/** @name Section 3 – Basic Types
 *  @{ */

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

/* Subsection #3.3: Specializations of Secondary Types*/

/** @brief Command tag (TPM_ST_NO_SESSIONS or TPM_ST_SESSIONS) */
typedef TPM_ST TPMI_ST_COMMAND_TAG;

/** @brief Handle for provisioning authorization (Owner, Platform, Endorsement) */
typedef TPM_HANDLE TPMI_RH_PROVISION;
/** @brief Legacy NV index handle */
typedef TPM_HANDLE TPMI_RH_NV_LEGACY_INDEX;
/** @brief NV index handle for authorization */
typedef TPM_HANDLE TPMI_RH_NV_AUTH;
/** @brief NV index handle */
typedef TPM_HANDLE TPMI_RH_NV_INDEX;
/** @brief Handle for loaded objects (transient range: 0x80000000-0x80FFFFFF) */
typedef TPM_HANDLE TPMI_DH_OBJECT;
/** @brief Hierarchy handle (Owner, Endorsement, Platform, or Null) */
typedef TPM_HANDLE TPMI_RH_HIERARCHY;

/** @brief Hash algorithm identifier */
typedef TPM_ALG_ID TPMI_ALG_HASH;
/** @brief Symmetric algorithm identifier */
typedef TPM_ALG_ID TPMI_ALG_SYM_OBJECT;
/** @brief Symmetric cipher mode identifier */
typedef TPM_ALG_ID TPMI_ALG_SYM_MODE;
/** @brief Cipher mode identifier */
typedef TPM_ALG_ID TPMI_ALG_CIPHER_MODE;
/** @brief Signature scheme identifier (RSASSA, RSAPSS, etc.) */
typedef TPM_ALG_ID TPMI_ALG_SIG_SCHEME;
/** @brief Public key algorithm identifier (RSA, ECC, etc.) */
typedef TPM_ALG_ID TPMI_ALG_PUBLIC;
/** @brief RSA-specific scheme identifier */
typedef TPM_ALG_ID TPMI_ALG_RSA_SCHEME;

/** @brief RSA key size in bits (e.g., 1024, 2048) */
typedef TPM_KEY_BITS TPMI_RSA_KEY_BITS;

/** @} */

/** @name Section 4 – Complex Types
 *  @{ */

/* Subsection #4.1: Hash and Digest Types */

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
    UINT16 size;
    BYTE buffer[TPM_MAX_SIGNATURE_SIZE]; // Max signature size (supports
                                         // RSA-2048 signatures)
} TPM2B_SIGNATURE;

typedef struct __packed {
    UINT16 size;
    BYTE buffer[TPM_MAX_KEY_SIZE]; // Max key size
} TPM2B_KEY;

typedef struct {
    TPMI_ALG_HASH hashAlg;
    TPMU_HA digest;
} TPMT_HA;

typedef union __packed {
    TPMT_HA digest;
    TPM_HANDLE handle;
} TPMU_NAME;

/**
 * @brief Variable-sized digest structure.
 * @note Used for hashes and digests throughout TPM commands.
 *       Size field indicates the number of valid bytes in buffer.
 */
typedef struct __packed {
    UINT16 size;  /**< Size of digest in bytes */
    BYTE buffer[sizeof(TPMU_HA)];  /**< Digest data */
} TPM2B_DIGEST;

/** @brief Authorization value (password or HMAC key) */
typedef TPM2B_DIGEST TPM2B_AUTH;

/**
 * @brief Object Name structure.
 * @note The Name is typically the hash of the object's public area,
 *       prefixed with the hash algorithm ID. Used for authorization
 *       and identification. See TPM 2.0 Part 1, Section 16.
 */
typedef struct __packed {
    UINT16 size;  /**< Size of name in bytes */
    BYTE buffer[sizeof(TPMU_NAME)];  /**< Name data (AlgID + Digest) */
} TPM2B_NAME;

/* Subsection #4.2: Signature and Ticket Types */

/**
 * @brief Signature scheme definition.
 * @note Specifies the signature algorithm (e.g., RSASSA, RSAPSS) and
 *       the hash algorithm to use. See TPM 2.0 Part 2, Table 145.
 */
typedef struct __packed {
    TPMI_ALG_SIG_SCHEME scheme;  /**< Signature scheme (RSASSA, RSAPSS, etc.) */
    TPMI_ALG_HASH hashAlg;       /**< Hash algorithm for the scheme */
} TPMT_SIG_SCHEME;

/**
 * @brief Hash check ticket.
 * @note Provides proof that a digest was created by the TPM.
 *       Used in TPM2_Sign for restricted keys. Tag must be TPM_ST_HASHCHECK.
 *       See TPM 2.0 Part 2, Section 11.4.6.
 */
typedef struct __packed {
    TPM_ST tag;              /**< Must be TPM_ST_HASHCHECK */
    TPM_HANDLE hierarchy;    /**< Hierarchy used to produce the ticket */
    TPM2B_DIGEST digest;     /**< HMAC over the digest */
} TPMT_TK_HASHCHECK;

/** @brief Signature verification ticket (same structure as TPMT_TK_HASHCHECK) */
typedef TPMT_TK_HASHCHECK TPMT_TK_VERIFIED;

/**
 * @brief Creation ticket.
 * @note Validates that an object was created by the TPM.
 *       Tag must be TPM_ST_CREATION. Returned by TPM2_Create and TPM2_CreatePrimary.
 *       See TPM 2.0 Part 2, Table 175.
 */
typedef TPMT_TK_HASHCHECK TPMT_TK_CREATION;

/**
 * @brief Signature structure.
 * @note Contains the signature algorithm, hash algorithm, and signature data.
 *       Returned by TPM2_Sign. See TPM 2.0 Part 2, Table 176.
 */
typedef struct __packed {
    TPMI_ALG_SIG_SCHEME sigAlg;  /**< Signature algorithm used */
    TPMI_ALG_HASH hashAlg;       /**< Hash algorithm used */
    TPM2B_SIGNATURE signature;   /**< Signature bytes */
} TPMT_SIGNATURE;

/* Subsection #4.3: Symmetric Encryption Types */

typedef struct __packed {
    TPMI_ALG_SYM_OBJECT algorithm; // TPM_ALG_* algorithm (AES, SM4, etc.)
    TPMU_SYM_KEY_BITS keyBits;     // Key size in bits (per algorithm)
    TPMU_SYM_MODE mode;            // Mode selector (ECB, CBC, CFB, OFB, CTR)
} TPMT_SYM_DEF_OBJECT;

typedef struct __packed {
    UINT16 size;
    BYTE buffer[TPM_MAX_IV_SIZE]; // Max IV size for AES
} TPM2B_IV;

typedef struct __packed {
    UINT16 size;
    BYTE buffer[TPM_MAX_MAX_BUFFER_SIZE]; // Larger buffer for symmetric
                                          // operations
} TPM2B_MAX_BUFFER;

/* Subsection #4.4: Asymmetric (RSA) Types */

typedef struct __packed {
    UINT16 size;
    BYTE buffer[TPM_MAX_KEY_SIZE];
} TPM2B_PUBLIC_KEY_RSA;

typedef struct __packed {
    UINT16 size;
    BYTE buffer[RSA_PRIVATE_SIZE];
} TPM2B_PRIVATE_KEY_RSA;

/* Subsection #4.5: PCR Types */

typedef struct __packed {
    TPMI_ALG_HASH hash;
    UINT8 sizeofSelect; /* lower bound PCR_SELECT_MIN */
    BYTE pcrSelect[PCR_SELECT_MAX];
} TPMS_PCR_SELECTION;

typedef struct __packed {
    UINT32 count;
    TPMS_PCR_SELECTION pcrSelections[HASH_COUNT];
} TPML_PCR_SELECTION;

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

/**
 * @brief Object attributes bit field.
 * @note Defines an object's use and authorization characteristics.
 *       See TPM 2.0 Part 2, Section 8.3.2. These attributes are critical
 *       for determining how a key can be used.
 */
typedef struct __packed {
    UINT32 Reserved0 : 1;              /**< Reserved (must be 0) */
    UINT32 fixedTPM : 1;               /**< Object hierarchy cannot change (non-duplicable) */
    UINT32 stClear : 1;                /**< Saved context invalid after TPM Reset */
    UINT32 Reserved1 : 1;              /**< Reserved */
    UINT32 fixedParent : 1;            /**< Parent cannot change (non-duplicable) */
    UINT32 sensitiveDataOrigin : 1;    /**< TPM generated the sensitive data */
    UINT32 userWithAuth : 1;           /**< Authorization via HMAC/Password allowed */
    UINT32 adminWithPolicy : 1;        /**< Authorization via policy required */
    UINT32 firmwareLimited : 1;        /**< Firmware-limited object */
    UINT32 svnLimited : 1;             /**< SVN-limited object */
    UINT32 noDA : 1;                   /**< Not subject to dictionary attack protection */
    UINT32 encryptedDuplication : 1;   /**< Object can be duplicated with encrypted wrapper */
    UINT32 Reserved2 : 4;              /**< Reserved */
    UINT32 restricted : 1;             /**< Key usage restricted to TPM-managed formats */
    UINT32 decrypt : 1;                /**< Private key used for decryption */
    UINT32 sign_encrypt : 1;           /**< Private key used for signing or symmetric encryption */
    UINT32 x509sign : 1;               /**< Key can sign X.509 certificates */
    UINT32 Reserved3 : 12;             /**< Reserved */
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

/* Subsection #4.7: Key and Object Types */

typedef struct __packed {
    UINT16 size;
    BYTE buffer[TPM_MAX_MAX_BUFFER_SIZE];
} TPM2B_CREATION_DATA;

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

/**
 * @brief Sensitive data for object creation.
 * @note Contains the authorization value and optional data to be sealed.
 *       For asymmetric keys, 'data' is typically empty as the TPM generates
 *       the private key. See TPM 2.0 Part 2, Table 133.
 */
typedef struct __packed {
    TPM2B_AUTH userAuth;          /**< Initial authorization value (password) */
    TPM2B_SENSITIVE_DATA data;    /**< Data to be sealed (empty for asymmetric keys) */
} TPMS_SENSITIVE_CREATE;

/**
 * @brief Variable-sized sensitive creation data.
 * @note Input to TPM2_Create and TPM2_CreatePrimary commands.
 *       Provides the initial authorization and sensitive data.
 */
typedef struct __packed {
    UINT16 size;                       /**< Size of sensitive structure */
    TPMS_SENSITIVE_CREATE sensitive;   /**< Sensitive creation data */
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

/**
 * @brief RSA key parameters.
 * @note Specifies symmetric encryption, signing scheme, key size, and exponent
 *       for an RSA key. See TPM 2.0 Part 2, Table 182.
 */
typedef struct __packed {
    TPMT_SYM_DEF_OBJECT symmetric;  /**< Symmetric algorithm for parameter encryption */
    TPMT_RSA_SCHEME scheme;         /**< RSA scheme (signing or encryption) */
    TPMI_RSA_KEY_BITS keyBits;      /**< RSA key size in bits (e.g., 2048) */
    UINT32 exponent;                /**< Public exponent (0 = default 65537) */
} TPMS_RSA_PARAMS;

/**
 * @brief Union of public area parameters.
 * @note Selector field 'type' in TPMT_PUBLIC determines which member is valid.
 *       See TPM 2.0 Part 2, Table 184.
 */
typedef struct __packed {
    // TPMS_KEYDHASH_PARAMS keyedHashDetail;
    // TPMS_SYMCIPHER_PARAMS symDetail;
    TPMS_RSA_PARAMS rsaDetail;  /**< RSA parameters (when type = TPM_ALG_RSA) */
    // TPMS_ECC_PARAMS eccDetail;
    // TPMS_ASYM_PARAMS asymDetail;
} TPMU_PUBLIC_PARAMS;

/**
 * @brief Union of unique identifiers for public area.
 * @note Contains type-specific public key material (e.g., RSA modulus).
 *       Selector field 'type' in TPMT_PUBLIC determines which member is valid.
 *       See TPM 2.0 Part 2, Table 185.
 */
typedef struct __packed {
    TPM2B_DIGEST keyedHash;           /**< For keyed hash objects */
    TPM2B_DIGEST sym;                 /**< For symmetric cipher objects */
    TPM2B_PUBLIC_KEY_RSA rsa;         /**< RSA public key (modulus) */
    // TPMS_ECC_POINT ecc;
    TPMS_DERIVE derive;               /**< For derivation parent */
} TPMU_PUBLIC_ID;

/**
 * @brief Public area of a TPM object.
 * @note Defines the complete public portion of a key or data object.
 *       The 'type' field selects which union members in 'parameters' and
 *       'unique' are valid. See TPM 2.0 Part 2, Table 184.
 *       Used in TPM2_Create, TPM2_CreatePrimary, TPM2_Load, and TPM2_ReadPublic.
 */
typedef struct __packed {
    TPMI_ALG_PUBLIC type;           /**< Algorithm/Object type (e.g., TPM_ALG_RSA) */
    TPMI_ALG_HASH nameAlg;          /**< Hash algorithm used for the Name of the object */
    TPMA_OBJECT objectAttributes;   /**< Object attribute flags (sign, decrypt, fixedTPM, etc.) */
    TPM2B_DIGEST authPolicy;        /**< Optional authorization policy digest */
    TPMU_PUBLIC_PARAMS parameters;  /**< Type-specific parameters (union, selected by 'type') */
    TPMU_PUBLIC_ID unique;          /**< Unique identifier (e.g., RSA public modulus) */
} TPMT_PUBLIC;

/**
 * @brief Variable-sized public area buffer.
 * @note Contains size prefix and TPMT_PUBLIC structure.
 *       Used as input template (TPM2_Create, TPM2_CreatePrimary) and
 *       output (TPM2_ReadPublic).
 */
typedef struct __packed {
    UINT16 size;              /**< Size of publicArea in bytes */
    TPMT_PUBLIC publicArea;   /**< The public area structure */
} TPM2B_PUBLIC;

typedef struct __packed {
    uint16_t size;
    uint8_t buffer[64];
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

/**
 * @brief Union of sensitive private key material.
 * @note Contains the actual private key data. Selector field 'sensitiveType'
 *       in TPMT_SENSITIVE determines which member is valid.
 *       See TPM 2.0 Part 2, Table 189.
 */
typedef union __packed {
    TPM2B_PRIVATE_KEY_RSA rsa;  /**< RSA private key (prime p * q) */
    // TPM2B_ECC_PARAMETER ecc;
    // TPM2B_SENSITIVE_DATA bits;
    // TPM2B_SYM_KEY sym;
    // TPM2B_PRIVATE_VENDOR_SPECIFIC any;
} TPMU_SENSITIVE_COMPOSITE;

/**
 * @brief Sensitive area of an object.
 * @note Contains the private key material, seed value, and authorization.
 *       This structure is always encrypted when stored or transmitted.
 *       See TPM 2.0 Part 2, Table 188.
 */
typedef struct __packed {
    TPMI_ALG_PUBLIC sensitiveType;         /**< Type of sensitive data (must match public type) */
    TPM2B_AUTH authValue;                  /**< Authorization value for the object */
    TPM2B_DIGEST seedValue;                /**< Seed for derived keys and obfuscation */
    TPMU_SENSITIVE_COMPOSITE sensitive;    /**< The actual private key material */
} TPMT_SENSITIVE;

/** @brief Internal buffer for private area data */
typedef struct __packed {
    UINT16 size;  /**< Size of encrypted private data */
    BYTE buffer[sizeof(TPMT_SENSITIVE) + SHA256_DIGEST_SIZE + 16];  /**< Encrypted buffer */
} _TPM2B_PRIVATE_BUFFER;

/**
 * @brief Encrypted private area of an object.
 * @note Returned by TPM2_Create and used as input to TPM2_Load.
 *       Contains the encrypted sensitive portion of the key, which includes
 *       the private key material and authorization value. The TPM encrypts
 *       this using the parent key's symmetric encryption key.
 *       See TPM 2.0 Part 2, Table 186.
 */
typedef union {
    _TPM2B_PRIVATE_BUFFER b;  /**< Buffer view */
    struct {
        UINT16 size;  /**< Size of encrypted private area */
        BYTE buffer[sizeof(TPMT_SENSITIVE) + SHA256_DIGEST_SIZE + 16];  /**< Encrypted data */
    };
} TPM2B_PRIVATE;

/**
 * @brief Complete object structure (public + private + metadata).
 * @note Internal TPM representation of a loaded object. Contains both
 *       public and sensitive areas, plus TPM-internal metadata.
 */
typedef struct __packed {
    OBJECT_ATTRIBUTES attributes;    /**< Internal object state flags */
    TPMT_PUBLIC publicArea;          /**< Public area (algorithm, attributes, public key) */
    TPMT_SENSITIVE sensitive;        /**< Sensitive area (private key, auth value) */
    TPM2B_NAME qualifiedName;        /**< Qualified Name (includes parent hierarchy) */
    TPMI_DH_OBJECT evictHandle;      /**< Persistent handle (if made persistent) */
    TPM2B_NAME name;                 /**< Name of the object (hash of public area) */
    TPMI_RH_HIERARCHY hierarchy;     /**< Hierarchy the object belongs to */
} OBJECT;

/* Subsection #4.8: Authorization Types */

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

/*
 * Wire-format auth areas (authSize prefix + content).
 * Used with MARSHAL/UNMARSHAL — no manual byte encoding needed.
 */
typedef struct __packed {
    UINT32 authSize; /* sizeof(TPMS_AUTH_COMMAND) */
    TPMS_AUTH_COMMAND auth;
} TPMS_AUTH_COMMAND_AREA;

typedef struct __packed {
    UINT32 authSize; /* sizeof(TPMS_AUTH_RESPONSE) */
    TPMS_AUTH_RESPONSE auth;
} TPMS_AUTH_RESPONSE_AREA;

/* Subsection #4.9: DRBG (Random Number Generator) Types */

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

/* Subsection #4.10: Command and Response Headers */

/**
 * @brief TPM command header.
 * @note Every TPM command begins with this header. The tag indicates
 *       whether authorization sessions are present. See TPM 2.0 Part 1, Section 6.
 */
typedef struct __packed {
    TPMI_ST_COMMAND_TAG tag;  /**< Command tag (TPM_ST_NO_SESSIONS or TPM_ST_SESSIONS) */
    UINT32 commandSize;       /**< Total size of command in bytes (including header) */
    TPM_CC commandCode;       /**< Command code identifier */
} tpm_cmd_header_t;

/**
 * @brief TPM response header.
 * @note Every TPM response begins with this header. The responseCode indicates
 *       success or failure. See TPM 2.0 Part 1, Section 6.
 */
typedef struct __packed {
    TPM_ST tag;            /**< Response tag (matches command tag) */
    UINT32 responseSize;   /**< Total size of response in bytes (including header) */
    TPM_RC responseCode;   /**< Response code (TPM_RC_SUCCESS or error) */
} tpm_rsp_header_t;

/* Subsection #4.11: TPM State Data */

/**
 * @brief State cleared on TPM2_Startup(CLEAR).
 * @note Contains hierarchy enables, platform policy/auth, and PCR values.
 *       This state is volatile and reset on each CLEAR startup.
 *       See TPM 2.0 Part 2, Section 13.1.
 */
typedef struct __packed {
    /* Hierarchy Control */
    BOOL shEnable;                   /**< Storage Hierarchy enabled */
    BOOL ehEnable;                   /**< Endorsement Hierarchy enabled */
    BOOL phEnableNV;                 /**< Platform Hierarchy enabled (NV) */
    TPMI_ALG_HASH platformAlg;       /**< Platform authorization algorithm */
    TPM2B_DIGEST platformPolicy;     /**< Platform authorization policy */
    TPM2B_AUTH platformAuth;         /**< Platform authorization value */

    /* PCR: SHA-256 bank (minimal) */
    BYTE pcr_sha256[TPM_PCR_COUNT][SHA256_DIGEST_SIZE];  /**< PCR registers (24 total) */
    /* ACT (empty) */
} state_clear_data;

/** @} */

/** @name Section 5 – Command I/O Structures
 *  @{ */

/* Subsection #5.1: Random Number Generation Commands */

/** @brief Input for TPM2_Startup — specifies CLEAR or STATE restart. */
typedef struct __packed {
    TPM_SU startupType; /**< @c TPM_SU_CLEAR or @c TPM_SU_STATE. */
} Startup_In;

/** @brief Input for TPM2_Shutdown — specifies CLEAR or STATE save. */
typedef struct __packed {
    TPM_SU shutdownType; /**< @c TPM_SU_CLEAR or @c TPM_SU_STATE. */
} Shutdown_In;

/** @brief Input for TPM2_SelfTest. */
typedef struct __packed {
    TPMI_YES_NO fullTest; /**< 1 = full test; 0 = incremental. */
} SelfTest_In;

/** @brief Input for TPM2_GetCapability. */
typedef struct __packed {
    TPM_CAP capability;   /**< Capability group (e.g. TPM_CAP_TPM_PROPERTIES). */
    TPM_PT property;      /**< First property to query. */
    UINT32 propertyCount; /**< Max number of properties to return. */
} GetCapability_In;

/** @brief Output for TPM2_GetCapability (simplified single-property). */
typedef struct __packed {
    TPMI_YES_NO moreData; /**< Non-zero if more data is available. */
    TPM_PT property;      /**< Returned property tag. */
    UINT32 value;         /**< Returned property value. */
} GetCapability_Out;

/** @brief Output for TPM2_GetTestResult. */
typedef struct __packed {
    TPM2B_MAX_BUFFER outData;   /**< Diagnostic data (empty in this impl). */
    TPM_RC testResult;          /**< Self-test result code. */
} GetTestResult_Out;

/** @brief Input for TPM2_FieldUpgradeData. */
typedef struct __packed {
    TPM2B_MAX_BUFFER fuData; /**< Firmware upgrade data block. */
} FieldUpgradeData_In;

// GetRandom
typedef struct __packed {
    UINT16 bytesRequested;
} GetRandom_In;

typedef struct __packed {
    TPM2B_DIGEST randomBytes;
} GetRandom_Out;

/* Subsection #5.2: NV Memory Commands */

/**
 * @brief Input for TPM2_NV_DefineSpace — defines a new NV index.
 * @note Creates a new NV storage area with specified attributes and size.
 *       Requires authorization from the specified hierarchy. See TPM 2.0 Part 3, Section 31.6.
 */
typedef struct __packed {
    TPMI_RH_PROVISION authHandle;  /**< Authorization handle (TPM_RH_OWNER or TPM_RH_PLATFORM) */
    TPM2B_AUTH auth;               /**< Authorization value */
    TPM2B_NV_PUBLIC publicInfo;    /**< NV index public area (attributes, size, etc.) */
} NV_DefineSpace_In;

/**
 * @brief Input for TPM2_NV_Write — writes data to NV index.
 * @note Writes data to a defined NV storage area. Requires proper authorization
 *       and the index must have write permission. See TPM 2.0 Part 3, Section 31.11.
 */
typedef struct __packed {
    TPMI_RH_NV_AUTH authHandle;    /**< Authorization handle */
    TPMI_RH_NV_INDEX nvIndex;      /**< NV index to write to */
    TPM2B_MAX_NV_BUFFER data;      /**< Data to write */
    UINT16 offset;                 /**< Byte offset into the NV area */
} NV_Write_In;

/**
 * @brief Input for TPM2_NV_Read — reads data from NV index.
 * @note Reads data from a defined NV storage area. Requires proper authorization
 *       and the index must have read permission. See TPM 2.0 Part 3, Section 31.9.
 */
typedef struct __packed {
    TPMI_RH_NV_AUTH authHandle;  /**< Authorization handle */
    TPMI_RH_NV_INDEX nvIndex;    /**< NV index to read from */
    UINT16 size;                 /**< Number of bytes to read */
    UINT16 offset;               /**< Byte offset into the NV area */
} NV_Read_In;

/**
 * @brief Output for TPM2_NV_Read.
 * @note Returns the requested data from the NV index.
 */
typedef struct __packed {
    TPM2B_MAX_NV_BUFFER data;  /**< Data read from NV index */
} NV_Read_Out;

/* Subsection #5.3: Cryptographic Commands */

/**
 * @brief Input for TPM2_Sign — signs a digest.
 * @note This command signs an externally provided hash using a signing key.
 *       The key must have the 'sign' attribute set. If the key is restricted,
 *       the validation ticket is required. The inScheme must match the key's
 *       default scheme or be TPM_ALG_NULL. See TPM 2.0 Part 3, Section 18.2
 *       and Table 109.
 */
typedef struct __packed {
    TPM_HANDLE keyHandle;            /**< Handle of the signing key */
    TPMT_SIG_SCHEME inScheme;        /**< Signing scheme to use */
    TPM2B_DIGEST digest;             /**< Digest to be signed */
    TPMT_TK_HASHCHECK validation;    /**< Proof that digest was TPM-created (for restricted keys) */
} Sign_In;

/**
 * @brief Output for TPM2_Sign.
 * @note Returns the signature structure containing the signature algorithm,
 *       hash algorithm, and signature bytes. See TPM 2.0 Part 3, Table 110.
 */
typedef struct __packed {
    TPMT_SIGNATURE signature;  /**< The resulting signature structure */
} Sign_Out;

/**
 * @brief Input for TPM2_VerifySignature — verifies a signature.
 * @note Validates a signature against a digest using a loaded public key.
 *       Returns a validation ticket on success. See TPM 2.0 Part 3, Section 18.6.
 */
typedef struct __packed {
    TPM_HANDLE keyHandle;      /**< Handle of the verification key */
    TPM2B_DIGEST digest;       /**< Digest that was signed */
    TPMT_SIGNATURE signature;  /**< Signature to verify */
} VerifySignature_In;

/**
 * @brief Output for TPM2_VerifySignature.
 * @note Returns a validation ticket if signature is valid.
 */
typedef struct __packed {
    TPMT_TK_VERIFIED validation;  /**< Validation ticket */
} VerifySignature_Out;

/**
 * @brief Input for TPM2_Hash — computes hash of data.
 * @note Hashes data and optionally returns a ticket proving the TPM computed the hash.
 *       The ticket can be used with restricted signing keys. See TPM 2.0 Part 3, Section 15.4.
 */
typedef struct __packed {
    TPM2B_MAX_BUFFER data;        /**< Data to hash */
    TPMI_ALG_HASH hashAlg;        /**< Hash algorithm to use (e.g., TPM_ALG_SHA256) */
    TPMI_RH_HIERARCHY hierarchy;  /**< Hierarchy for the ticket */
} Hash_In;

/**
 * @brief Output for TPM2_Hash.
 * @note Returns the computed digest and validation ticket.
 */
typedef struct __packed {
    TPM2B_DIGEST digest;           /**< Computed hash digest */
    TPMT_TK_HASHCHECK validation;  /**< Validation ticket */
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

/* Subsection #5.4: Key Lifecycle Management Commands */

/**
 * @brief Input for TPM2_CreatePrimary — creates a primary object.
 * @note This command creates a Primary Object from a hierarchy seed.
 *       The object is derived deterministically from the seed and template,
 *       so calling with the same parameters always produces the same key.
 *       The object is loaded but the private area is NOT returned.
 *       See TPM 2.0 Part 3, Section 24.1 and Table 174.
 */
typedef struct __packed {
    TPMI_RH_HIERARCHY primaryHandle;    /**< Hierarchy handle (TPM_RH_OWNER, TPM_RH_ENDORSEMENT, etc.) */
    TPM2B_SENSITIVE_CREATE inSensitive; /**< Sensitive data (authorization value) */
    TPM2B_PUBLIC inPublic;              /**< Public template defining key attributes */
    TPM2B_DATA outsideInfo;             /**< Data included in creation data for linkage */
    TPML_PCR_SELECTION creationPCR;     /**< PCRs to include in creation data */
} CreatePrimary_In;

/**
 * @brief Output for TPM2_CreatePrimary.
 * @note Returns the handle to the loaded primary object, its public area,
 *       creation data, and validation ticket. The private area is NOT returned.
 *       See TPM 2.0 Part 3, Table 175.
 */
typedef struct __packed {
    TPM_HANDLE objectHandle;            /**< Handle for the loaded Primary Object */
    TPM2B_PUBLIC outPublic;             /**< Public portion of the created object */
    TPM2B_CREATION_DATA creationData;   /**< Data linking the object to the TPM */
    TPM2B_DIGEST creationHash;          /**< Digest of the creation data */
    TPMT_TK_CREATION creationTicket;    /**< Ticket used to validate creation data */
    TPM2B_NAME name;                    /**< Name of the created object */
} CreatePrimary_Out;

/**
 * @brief Input for TPM2_Create — creates a child object.
 * @note This command generates a key pair (child object) under a loaded parent.
 *       Unlike CreatePrimary, this DOES return the encrypted private portion,
 *       allowing the key to be stored externally and reloaded with TPM2_Load.
 *       The TPM generates the private key for asymmetric keys.
 *       See TPM 2.0 Part 3, Section 12.1 and Table 18.
 */
typedef struct __packed {
    TPMI_DH_OBJECT parentHandle;        /**< Handle of the parent key (must be loaded) */
    TPM2B_SENSITIVE_CREATE inSensitive; /**< Initial sensitive data (authorization value) */
    TPM2B_PUBLIC inPublic;              /**< Public template for the new key */
    TPM2B_DATA outsideInfo;             /**< Data for creation linkage */
    TPML_PCR_SELECTION creationPCR;     /**< PCR selection for creation data */
} Create_In;

/**
 * @brief Output for TPM2_Create.
 * @note Returns both the encrypted private portion (outPrivate) and public area.
 *       The private portion is encrypted using the parent's symmetric key.
 *       These can be stored and later loaded with TPM2_Load.
 *       See TPM 2.0 Part 3, Table 19.
 */
typedef struct __packed {
    TPM2B_PRIVATE outPrivate;           /**< Encrypted private portion of the object */
    TPM2B_PUBLIC outPublic;             /**< Public portion of the created object */
    TPM2B_CREATION_DATA creationData;   /**< Creation data structure */
    TPM2B_DIGEST creationHash;          /**< Digest of creation data */
    TPMT_TK_CREATION creationTicket;    /**< Validation ticket */
} Create_Out;

/**
 * @brief Input for TPM2_Load — loads a created object.
 * @note This command loads an object (created by TPM2_Create) into TPM memory.
 *       The TPM verifies the integrity of the private blob before decryption
 *       and validates that the public and private portions are cryptographically
 *       bound. See TPM 2.0 Part 3, Section 12.2 and Table 20.
 */
typedef struct __packed {
    TPMI_DH_OBJECT parentHandle;  /**< Handle of the parent key */
    TPM2B_PRIVATE inPrivate;      /**< Encrypted private portion of the object */
    TPM2B_PUBLIC inPublic;        /**< Public portion of the object */
} Load_In;

/**
 * @brief Output for TPM2_Load.
 * @note Returns a transient handle for the loaded object and its Name.
 *       The handle can be used in cryptographic operations (Sign, Decrypt, etc.).
 *       See TPM 2.0 Part 3, Table 21.
 */
typedef struct __packed {
    TPM_HANDLE objectHandle;  /**< Transient handle for the loaded object */
    TPM2B_NAME name;          /**< Name of the loaded object (hash of public area) */
} Load_Out;

/**
 * @brief Input for TPM2_ReadPublic — reads public area of an object.
 * @note This command retrieves the public area of a loaded object.
 *       No authorization is required. Used to export the public key
 *       for external signature verification. See TPM 2.0 Part 3,
 *       Section 12.4 and Table 24.
 */
typedef struct __packed {
    TPMI_DH_OBJECT objectHandle;  /**< TPM handle of the object to read */
} ReadPublic_In;

/**
 * @brief Output for TPM2_ReadPublic.
 * @note Returns the public area, Name, and Qualified Name.
 *       The public area contains the public key (e.g., RSA modulus and exponent)
 *       which can be used to verify signatures externally.
 *       See TPM 2.0 Part 3, Table 25.
 */
typedef struct __packed {
    TPM2B_PUBLIC outPublic;     /**< Public area structure */
    TPM2B_NAME name;            /**< Name of the object */
    TPM2B_NAME qualifiedName;   /**< Qualified Name of the object */
} ReadPublic_Out;

/** @} */

/** @name Section 6 – Function Prototypes
 *  @{ */

/* Subsection 6.1: Marshalling / Unmarshalling */

/** @brief Unmarshal @p size bytes from @p fifo into @p data. */
void unmarshal(void *data, size_t size, Fifo8 *fifo);
/** @brief Marshal @p size bytes of @p data into @p fifo. */
void marshal(Fifo8 *fifo, const void *data, size_t size);

/* Subsection 6.2: Helper Functions */

/* ---- NV Storage ---- */

/** @brief Look up an NV index and return its descriptor. */
NV_INDEX *NvGetIndexInfo(TPM_HANDLE nvHandle, NV_REF *locator);
/** @brief Validate write access to an NV index. */
TPM_RC NvWriteAccessChecks(TPM_HANDLE authHandle, TPM_HANDLE nvHandle,
                           TPMA_NV attributes);
/** @brief Write data to an NV index’s data area. */
TPM_RC NvWriteIndexData(NV_INDEX *nvIndex, UINT32 offset, UINT32 size,
                        void *data);
/** @brief Validate read access to an NV index. */
TPM_RC NvReadAccessChecks(TPM_HANDLE authHandle, TPM_HANDLE nvHandle,
                          TPMA_NV attributes);
/** @brief Read data bytes from an NV index’s data area. */
void NvGetIndexData(NV_INDEX *nvIndex, NV_REF locator, UINT32 offset,
                    UINT16 size, void *data);

/** @brief Define a new NV index with full attribute checks. */
TPM_RC NvDefineSpace(TPMI_RH_PROVISION authHandle, TPM2B_AUTH *auth,
                     TPMS_NV_PUBLIC *publicInfo, TPM_RC blameAuthHandle,
                     TPM_RC blameAuth, TPM_RC blamePublic);
/** @brief Connect TPM device memory to the NV storage module. */
BOOL NvInit(void *memory, size_t size, state_clear_data *tpm_saved_state);

/** @name State Machine Helpers
 *  Functions implemented in @ref tpm_state_machine.c.
 *  @{ */
struct S32k358TPMState;

/** @brief Reset all state-machine flags to power-on defaults. */
void tpm_state_machine_reset(struct S32k358TPMState *s);

/**
 * @brief Check whether @p cc is allowed in the current TPM mode.
 * @param[in,out] s      Device state.
 * @param[in]     cc     Command code to check.
 * @param[out]    rc_out Receives the rejection code on failure.
 * @return @c true if the command may proceed.
 */
bool tpm_command_allowed_in_current_mode(struct S32k358TPMState *s, TPM_CC cc,
                                         TPM_RC *rc_out);

/** @brief State-machine Startup handler. */
TPM_RC TPM2_Startup_SM(struct S32k358TPMState *s, Startup_In *in);
/** @brief State-machine Shutdown handler. */
TPM_RC TPM2_Shutdown_SM(struct S32k358TPMState *s, Shutdown_In *in);
/** @brief State-machine SelfTest handler. */
TPM_RC TPM2_SelfTest_SM(struct S32k358TPMState *s, SelfTest_In *in);
/** @brief State-machine GetTestResult handler. */
TPM_RC TPM2_GetTestResult_SM(struct S32k358TPMState *s, GetTestResult_Out *out);
/** @brief State-machine GetCapability handler. */
TPM_RC TPM2_GetCapability_SM(struct S32k358TPMState *s, GetCapability_In *in,
                             GetCapability_Out *out);
/** @brief State-machine FieldUpgradeStart handler. */
TPM_RC TPM2_FieldUpgradeStart_SM(struct S32k358TPMState *s);
/** @brief State-machine FieldUpgradeData handler. */
TPM_RC TPM2_FieldUpgradeData_SM(struct S32k358TPMState *s,
                                FieldUpgradeData_In *in);
/** @} */

/* Subsection 6.3: TPM Commands */

/** @brief Generate random bytes (Spec Section 5.1). */
TPM_RC TPM2_GetRandom(GetRandom_In *in, GetRandom_Out *out);

/* ---- Cryptographic Primitives ---- */

/**
 * @brief Sign data using a loaded key (TPM2_Sign).
 * @param[in]  in   Input parameters (keyHandle, digest, scheme, validation).
 * @param[out] out  Output signature.
 * @return TPM_RC_SUCCESS on success, or error code.
 * @note The key must have the 'sign' attribute. If restricted, validation ticket required.
 *       See TPM 2.0 Part 3, Section 18.2.
 */
TPM_RC TPM2_Sign(Sign_In *in, Sign_Out *out);

/**
 * @brief Verify a signature against a loaded key (TPM2_VerifySignature).
 * @param[in]  in   Input parameters (keyHandle, digest, signature).
 * @param[out] out  Validation ticket on success.
 * @return TPM_RC_SUCCESS if signature is valid, or error code.
 * @note See TPM 2.0 Part 3, Section 18.6.
 */
TPM_RC TPM2_VerifySignature(VerifySignature_In *in, VerifySignature_Out *out);

/**
 * @brief Compute a hash of the supplied data (TPM2_Hash).
 * @param[in]  in   Input parameters (data, hash algorithm, hierarchy).
 * @param[out] out  Computed digest and validation ticket.
 * @return TPM_RC_SUCCESS on success, or error code.
 * @note See TPM 2.0 Part 3, Section 15.4.
 */
TPM_RC TPM2_Hash(Hash_In *in, Hash_Out *out);
/** @brief Symmetric encrypt/decrypt using a loaded key (Spec Section 5.6). */
TPM_RC TPM2_EncryptDecrypt2(EncryptDecrypt2_In *in, EncryptDecrypt2_Out *out);
/** @brief RSA encryption using a loaded public key. */
TPM_RC TPM2_RSA_Encrypt(RSA_Encrypt_In *in, RSA_Encrypt_Out *out);
/** @brief RSA decryption using a loaded private key. */
TPM_RC TPM2_RSA_Decrypt(RSA_Decrypt_In *in, RSA_Decrypt_Out *out);

/* ---- Key Lifecycle Management ---- */

/**
 * @brief Create a primary key from a hierarchy seed (TPM2_CreatePrimary).
 * @param[in]  in   Input parameters (hierarchy, sensitive data, public template).
 * @param[out] out  Output handle, public area, creation data, and ticket.
 * @return TPM_RC_SUCCESS on success, or error code.
 * @note Creates a Primary Object from a hierarchy seed (deterministic).
 *       The object is loaded but the private area is NOT returned.
 *       Calling with the same parameters always produces the same key.
 *       See TPM 2.0 Part 3, Section 24.1 and Tables 174-175.
 */
TPM_RC TPM2_CreatePrimary(CreatePrimary_In *in, CreatePrimary_Out *out);

/**
 * @brief Create a child key under a loaded parent (TPM2_Create).
 * @param[in]  in   Input parameters (parent handle, sensitive data, public template).
 * @param[out] out  Encrypted private area, public area, creation data, and ticket.
 * @return TPM_RC_SUCCESS on success, or error code.
 * @note Generates a key pair under a loaded parent. Returns encrypted private
 *       portion which can be stored externally and reloaded with TPM2_Load.
 *       See TPM 2.0 Part 3, Section 12.1 and Tables 18-19.
 */
TPM_RC TPM2_Create(Create_In *in, Create_Out *out);

/**
 * @brief Load a key-pair into a transient object slot (TPM2_Load).
 * @param[in]  in   Input parameters (parent handle, encrypted private, public areas).
 * @param[out] out  Object handle and Name.
 * @return TPM_RC_SUCCESS on success, or error code.
 * @note Loads an object created by TPM2_Create into TPM memory. Verifies
 *       integrity and cryptographic binding before decryption.
 *       See TPM 2.0 Part 3, Section 12.2 and Tables 20-21.
 */
TPM_RC TPM2_Load(Load_In *in, Load_Out *out);

/**
 * @brief Read the public area of a loaded object (TPM2_ReadPublic).
 * @param[in]  in   Input parameters (object handle).
 * @param[out] out  Public area, Name, and Qualified Name.
 * @return TPM_RC_SUCCESS on success, or error code.
 * @note Retrieves the public area of a loaded object. No authorization required.
 *       Used to export public keys for external signature verification.
 *       See TPM 2.0 Part 3, Section 12.4 and Tables 24-25.
 */
TPM_RC TPM2_ReadPublic(ReadPublic_In *in, ReadPublic_Out *out);

/* ---- NV Memory ---- */

/**
 * @brief Define a new NV index (TPM2_NV_DefineSpace).
 * @param[in] in  Input parameters (auth handle, public info).
 * @return TPM_RC_SUCCESS on success, or error code.
 * @note Creates a new NV storage area with specified attributes and size.
 *       See TPM 2.0 Part 3, Section 31.6.
 */
TPM_RC TPM2_NV_DefineSpace(NV_DefineSpace_In *in);

/**
 * @brief Write data to a defined NV index (TPM2_NV_Write).
 * @param[in] in  Input parameters (auth handle, NV index, data, offset).
 * @return TPM_RC_SUCCESS on success, or error code.
 * @note Writes data to NV storage. Requires proper authorization.
 *       See TPM 2.0 Part 3, Section 31.11.
 */
TPM_RC TPM2_NV_Write(NV_Write_In *in);

/**
 * @brief Read data from a defined NV index (TPM2_NV_Read).
 * @param[in]  in   Input parameters (auth handle, NV index, size, offset).
 * @param[out] out  Data read from NV index.
 * @return TPM_RC_SUCCESS on success, or error code.
 * @note Reads data from NV storage. Requires proper authorization.
 *       See TPM 2.0 Part 3, Section 31.9.
 */
TPM_RC TPM2_NV_Read(NV_Read_In *in, NV_Read_Out *out);

/** @} */

#endif /* TPM2_SPEC_PROTOCOL_H */
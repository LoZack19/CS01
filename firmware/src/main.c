#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include "S32K358.h"
#include "Lpuart_Uart_Ip.h"
#include "IntCtrl_Ip.h"
#include "FreeRTOS.h"
#include "sha256.h"
#include <stdio.h>
#include "tpm2_spec_protocol.h"
#include "tpm_tests_config.h"
#include "tpm_marshal.h"

#define LPUART_INSTANCE (3U) // Usare LPUART3

// Debug logging - set to 1 to enable verbose output
#define TPM_DEBUG 1

#if TPM_DEBUG
#define DBG_PRINT(msg)                                             \
    do {                                                           \
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)(msg), \
                                strlen(msg), portMAX_DELAY);       \
    } while (0)

#define DBG_PRINTF(fmt, ...)                                          \
    do {                                                              \
        char _dbg_buf[128];                                           \
        int _dbg_len =                                                \
            snprintf(_dbg_buf, sizeof(_dbg_buf), fmt, ##__VA_ARGS__); \
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)_dbg_buf, \
                                _dbg_len, portMAX_DELAY);             \
    } while (0)
#else
#define DBG_PRINT(msg)       ((void)0)
#define DBG_PRINTF(fmt, ...) ((void)0)
#endif

// MMIO Register Definitions
#define TPM_BASE 0x40000000

#define TPM_ACCESS \
    (*(volatile uint8_t *)(TPM_BASE + 0x0000)) // Used to request and check
                                               // access to the TPM
#define TPM_STS (*(volatile uint32_t *)(TPM_BASE + 0x0018)) // only 3 bytes used
#define TPM_DATA_FIFO                 \
    (*(volatile uint8_t *)(TPM_BASE + \
                           0x0024)) // The FIFO register for sending commands
                                    // and reading responses.

// Bitmask Constants
#define TPM_ACCESS_REQUEST_USE  0x02
#define TPM_ACCESS_ACTIVE_LOCAL 0x20

#define TPM_STS_COMMAND_READY 0x40
#define TPM_STS_GO            0x20
#define TPM_STS_DATA_AVAIL    0x10
#define TPM_STS_EXPECT        0x08

// TPM Utilities

const char *string_from_TPM_RC(TPM_RC rc) {
    switch (rc) {
    /*
     * Important: several TPM_RC_* macros in our header are *modifiers* or
     * *aliases* (e.g. TPM_RC_H, TPM_RC_P, TPM_RC_1, RC_VER1, TPM_RCS_*).
     * They intentionally share integer values and are not distinguishable
     * at runtime, so they must NOT appear as distinct switch labels.
     */
    case TPM_RC_SUCCESS:
        return "TPM_RC_SUCCESS";
    case TPM_RC_BAD_TAG:
        return "TPM_RC_BAD_TAG";

    /* Ver1 family (RC_VER1 is a base, not a standalone code) */
    case TPM_RC_FAILURE:
        return "TPM_RC_FAILURE";
    case TPM_RC_COMMAND_SIZE:
        return "TPM_RC_COMMAND_SIZE";
    case TPM_RC_COMMAND_CODE:
        return "TPM_RC_COMMAND_CODE";
    case TPM_RC_NV_RANGE:
        return "TPM_RC_NV_RANGE";
    case TPM_RC_NV_LOCKED:
        return "TPM_RC_NV_LOCKED";
    case TPM_RC_NV_AUTHORIZATION:
        return "TPM_RC_NV_AUTHORIZATION";
    case TPM_RC_NV_UNINITIALIZED:
        return "TPM_RC_NV_UNINITIALIZED";
    case TPM_RC_NV_SPACE:
        return "TPM_RC_NV_SPACE";
    case TPM_RC_NV_DEFINED:
        return "TPM_RC_NV_DEFINED";

    /* Format-1 style base codes */
    case TPM_RC_ATTRIBUTES:
        return "TPM_RC_ATTRIBUTES";
    case TPM_RC_HASH:
        return "TPM_RC_HASH";
    case TPM_RC_VALUE:
        return "TPM_RC_VALUE";
    case TPM_RC_HIERARCHY:
        return "TPM_RC_HIERARCHY";
    case TPM_RC_MODE:
        return "TPM_RC_MODE";
    case TPM_RC_HANDLE:
        return "TPM_RC_HANDLE";
    case TPM_RCS_SIZE:
        return "TPM_RCS_SIZE";
    case TPM_RC_SIGNATURE:
        return "TPM_RC_SIGNATURE";
    case TPM_RC_KEY:
        return "TPM_RC_KEY";
    case TPM_RC_KEY_SIZE:
        return "TPM_RC_KEY_SIZE";
    case TPM_RC_BINDING:
        return "TPM_RC_BINDING";
    case TPM_RC_SEQUENCE:
        return "TPM_RC_SEQUENCE";

    default:
        return "UNKNOWN_RC";
    }
}

int assert_count = 0;
int assert_failures = 0;

void assert(bool expression, const char *msg, const char *expected,
            const char *actual) {
    if (!expression) {
        if (msg != NULL) {
            Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)msg,
                                    strlen(msg), portMAX_DELAY);
        }

        // Expected: <exp>, got: <got>
        if (expected != NULL) {
            Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE,
                                    (uint8_t *)"Expected: ", 10, portMAX_DELAY);

            Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)expected,
                                    strlen(expected), portMAX_DELAY);
        }

        if (actual != NULL) {
            Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)", got: ", 7,
                                    portMAX_DELAY);

            Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)actual,
                                    strlen(actual), portMAX_DELAY);
        }

        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"\n", 1,
                                portMAX_DELAY);

        assert_failures++;
    }
    assert_count++;
}

void assert_report(void) {
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)"Assert Report\n", 14,
                            portMAX_DELAY);

    char buffer[50];
    int len =
        snprintf(buffer, sizeof(buffer), "Total asserts: %d\n", assert_count);
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)buffer, len,
                            portMAX_DELAY);

    len = snprintf(buffer, sizeof(buffer), "Failed asserts: %d\n",
                   assert_failures);
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE, (uint8_t *)buffer, len,
                            portMAX_DELAY);

    if (assert_failures == 0) {
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE,
                                (uint8_t *)"All tests passed!\n", 18,
                                portMAX_DELAY);
    } else {
        Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE,
                                (uint8_t *)"Some tests failed!\n", 19,
                                portMAX_DELAY);
    }
}

// TPM Interface

bool tpm_send_rdy(void) {
    return TPM_STS & TPM_STS_EXPECT;
}

bool tpm_receive_rdy(void) {
    return TPM_STS & TPM_STS_DATA_AVAIL;
}

/**
 * @brief Send data into TPM
 * @param[in] data Data to be sent into the TPM
 * @param[in] size Amount of data to be sent
 *
 * @note This could be made more efficient by using burstSize instead of waiting
 *       on every byte.
 */
void tpm_send(const void *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        while (!tpm_send_rdy())
            ;
        TPM_DATA_FIFO = ((uint8_t *)data)[i];
    }
}

/**
 * @brief Receive data from TPM
 * @param[out] data Storage for the received data
 * @param[in] size Amount of data to retrieve
 *
 * @note This could be made more efficient by using burstSize instead of waiting
 *       on every byte.
 */
void tpm_receive(void *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        while (!tpm_receive_rdy())
            ;
        ((uint8_t *)data)[i] = TPM_DATA_FIFO;
    }
}

/**
 * @brief Request TPM locality and busy wait until it's granted
 */
static inline void tpm_wait_access(void) {
    TPM_ACCESS = TPM_ACCESS_REQUEST_USE;
    while (!(TPM_ACCESS & TPM_ACCESS_ACTIVE_LOCAL))
        ;
}

/**
 * @brief Notify TPM that a command is about to be sent in
 */
static inline void tpm_command_ready(void) {
    TPM_STS |= TPM_STS_COMMAND_READY;
}

/**
 * @brief Start the execution of a command
 */
static inline void tpm_go(void) {
    TPM_STS |= TPM_STS_GO;
}

// TPM Commands

static inline size_t min_size(size_t a, size_t b) {
    return (a < b) ? a : b;
}

static void tpm_drain_bytes(size_t size) {
    uint8_t sink[16];
    while (size > 0) {
        size_t chunk = min_size(size, sizeof(sink));
        tpm_receive(sink, chunk);
        size -= chunk;
    }
}

/* ===========================================================================
 * Raw command helper — sends an arbitrary header + payload and returns
 * the response header.  Used by transport / framing / error negative tests.
 * ===========================================================================
 */
#if defined(TPM_TEST_ENABLE_TRANSPORT_NEGATIVE) || \
    defined(TPM_TEST_ENABLE_ERROR_HANDLING)
static tpm_rsp_header_t tpm_send_raw_command(uint16_t tag,
                                             uint32_t commandCode,
                                             const void *payload,
                                             size_t payload_size) {
    tpm_cmd_header_t cmd = {
        .tag = tag,
        .commandSize = (uint32_t)(sizeof(cmd) + payload_size),
        .commandCode = commandCode,
    };

    tpm_command_ready();
    tpm_send(&cmd, sizeof(cmd));
    if (payload != NULL && payload_size > 0) {
        tpm_send(payload, payload_size);
    }
    tpm_go();

    tpm_rsp_header_t rsp;
    tpm_receive(&rsp, sizeof(rsp));

    /* Drain any remaining response bytes */
    size_t remaining = 0;
    if (rsp.responseSize >= sizeof(rsp) && rsp.responseSize <= 4096) {
        remaining = (size_t)rsp.responseSize - sizeof(rsp);
    }
    tpm_drain_bytes(remaining);

    return rsp;
}

/**
 * @brief Send a raw command with a deliberately wrong commandSize field.
 * The actual payload sent matches payload_size, but the header's
 * commandSize is set to the caller-provided value.
 */
static tpm_rsp_header_t tpm_send_raw_command_bad_size(uint16_t tag,
                                                      uint32_t commandCode,
                                                      uint32_t declared_size,
                                                      const void *payload,
                                                      size_t payload_size) {
    tpm_cmd_header_t cmd = {
        .tag = tag,
        .commandSize = declared_size,
        .commandCode = commandCode,
    };

    tpm_command_ready();
    tpm_send(&cmd, sizeof(cmd));
    if (payload != NULL && payload_size > 0) {
        tpm_send(payload, payload_size);
    }
    tpm_go();

    tpm_rsp_header_t rsp;
    tpm_receive(&rsp, sizeof(rsp));

    size_t remaining = 0;
    if (rsp.responseSize >= sizeof(rsp) && rsp.responseSize <= 4096) {
        remaining = (size_t)rsp.responseSize - sizeof(rsp);
    }
    tpm_drain_bytes(remaining);

    return rsp;
}
#endif /* TPM_TEST_ENABLE_TRANSPORT_NEGATIVE || ERROR_HANDLING */

/* ===========================================================================
 * TPM_ST_SESSIONS Helper Functions
 * ===========================================================================
 */

/* Authorization area sizes using the wire-format structs */
#define AUTH_CMD_AREA_SIZE sizeof(TPMS_AUTH_COMMAND_AREA)
#define AUTH_RSP_AREA_SIZE sizeof(TPMS_AUTH_RESPONSE_AREA)

/**
 * @brief Send empty password authorization area using __packed struct.
 */
static void tpm_send_auth_area(void) {
    TPMS_AUTH_COMMAND_AREA area = {
        .authSize = sizeof(TPMS_AUTH_COMMAND),
        .auth = {
            .sessionHandle = TPM_RS_PW,
            /* nonce, sessionAttributes, hmac: zero-init */
        }};
    tpm_send(&area, sizeof(area));
}

/**
 * @brief Skip authorization response area in TPM_ST_SESSIONS responses.
 */
static void skip_auth_response_area(void) {
    TPMS_AUTH_RESPONSE_AREA area;
    tpm_receive(&area, sizeof(area));
}

#ifndef TPM2_InOut
#define TPM2_InOut(F)                                                        \
    TPM_RC TPM2_##F(F##_In *in, F##_Out *out) {                              \
        tpm_rsp_header_t rsp;                                                \
                                                                             \
        tpm_cmd_header_t cmd = {.tag = TPM_ST_NO_SESSIONS,                   \
                                .commandSize = sizeof(cmd) + sizeof(*in),    \
                                .commandCode = TPM_CC_##F};                  \
                                                                             \
        DBG_PRINTF("[DBG] TPM2_" #F                                          \
                   ": Sending cmd (tag=0x%04X, size=%lu, code=0x%08lX)\n",   \
                   cmd.tag, (unsigned long)cmd.commandSize,                  \
                   (unsigned long)cmd.commandCode);                          \
                                                                             \
        tpm_command_ready();                                                 \
        tpm_send(&cmd, sizeof(cmd));                                         \
        tpm_send(in, sizeof(*in));                                           \
                                                                             \
        tpm_go();                                                            \
                                                                             \
        tpm_receive(&rsp, sizeof(rsp));                                      \
        DBG_PRINTF("[DBG] TPM2_" #F                                          \
                   ": Received rsp (tag=0x%04X, size=%lu, rc=0x%08lX)\n",    \
                   rsp.tag, (unsigned long)rsp.responseSize,                 \
                   (unsigned long)rsp.responseCode);                         \
                                                                             \
        size_t remaining = 0;                                                \
        if (rsp.responseSize >= sizeof(rsp) && rsp.responseSize <= 4096) {   \
            remaining = (size_t)rsp.responseSize - sizeof(rsp);              \
        }                                                                    \
        DBG_PRINTF("[DBG] TPM2_" #F ": remaining=%lu bytes\n",               \
                   (unsigned long)remaining);                                \
                                                                             \
        if (out != NULL) {                                                   \
            memset(out, 0, sizeof(*out));                                    \
        }                                                                    \
                                                                             \
        if (rsp.responseCode != TPM_RC_SUCCESS) {                            \
            DBG_PRINTF("[DBG] TPM2_" #F                                      \
                       ": Error response, draining %lu bytes\n",             \
                       (unsigned long)remaining);                            \
            tpm_drain_bytes(remaining);                                      \
            return rsp.responseCode;                                         \
        }                                                                    \
                                                                             \
        if (out != NULL) {                                                   \
            size_t to_read = min_size(remaining, sizeof(*out));              \
            DBG_PRINTF("[DBG] TPM2_" #F                                      \
                       ": Reading %lu bytes to out (out size=%lu)\n",        \
                       (unsigned long)to_read, (unsigned long)sizeof(*out)); \
            tpm_receive(out, to_read);                                       \
            tpm_drain_bytes(remaining - to_read);                            \
        } else {                                                             \
            tpm_drain_bytes(remaining);                                      \
        }                                                                    \
                                                                             \
        return rsp.responseCode;                                             \
    }
#endif

#ifndef TPM2_In
#define TPM2_In(F)                                                         \
    TPM_RC TPM2_##F(F##_In *in) {                                          \
        tpm_rsp_header_t rsp;                                              \
                                                                           \
        tpm_cmd_header_t cmd = {.tag = TPM_ST_NO_SESSIONS,                 \
                                .commandSize = sizeof(cmd) + sizeof(*in),  \
                                .commandCode = TPM_CC_##F};                \
                                                                           \
        DBG_PRINTF("[DBG] TPM2_" #F                                        \
                   ": Sending cmd (tag=0x%04X, size=%lu, code=0x%08lX)\n", \
                   cmd.tag, (unsigned long)cmd.commandSize,                \
                   (unsigned long)cmd.commandCode);                        \
                                                                           \
        tpm_command_ready();                                               \
        tpm_send(&cmd, sizeof(cmd));                                       \
        tpm_send(in, sizeof(*in));                                         \
                                                                           \
        tpm_go();                                                          \
                                                                           \
        tpm_receive(&rsp, sizeof(rsp));                                    \
        DBG_PRINTF("[DBG] TPM2_" #F                                        \
                   ": Received rsp (tag=0x%04X, size=%lu, rc=0x%08lX)\n",  \
                   rsp.tag, (unsigned long)rsp.responseSize,               \
                   (unsigned long)rsp.responseCode);                       \
                                                                           \
        size_t remaining = 0;                                              \
        if (rsp.responseSize >= sizeof(rsp) && rsp.responseSize <= 4096) { \
            remaining = (size_t)rsp.responseSize - sizeof(rsp);            \
        }                                                                  \
        tpm_drain_bytes(remaining);                                        \
                                                                           \
        return rsp.responseCode;                                           \
    }
#endif

#ifdef TPM_TEST_ENABLE_NV_DEFINE
TPM2_In(NV_DefineSpace);
#endif

#ifdef TPM_TEST_ENABLE_NV_WRITE_READ
TPM2_In(NV_Write);
TPM2_InOut(NV_Read);
#endif

#ifdef TPM_TEST_ENABLE_SIGN
TPM2_InOut(Sign)
#endif

#ifdef TPM_TEST_ENABLE_VERIFY_SIGNATURE
    TPM2_InOut(VerifySignature)
#endif

#ifdef TPM_TEST_ENABLE_HASH
        TPM2_InOut(Hash)
#endif

#ifdef TPM_TEST_ENABLE_ENCRYPT_DECRYPT2
            TPM2_InOut(EncryptDecrypt2)
#endif

#ifdef TPM_TEST_ENABLE_RSA_ENCRYPT_DECRYPT
                TPM2_InOut(RSA_Encrypt) TPM2_InOut(RSA_Decrypt)
#endif

/* Key Management Commands */
#ifdef TPM_TEST_ENABLE_CREATEPRIMARY
                    TPM2_InOut(CreatePrimary)
#endif

#ifdef TPM_TEST_ENABLE_CREATE
                        TPM2_InOut(Create)
#endif

#ifdef TPM_TEST_ENABLE_LOAD
                            TPM2_InOut(Load)
#endif

#ifdef TPM_TEST_ENABLE_READPUBLIC
                                TPM2_InOut(ReadPublic);
#endif

#ifdef TPM_TEST_ENABLE_OBJECTCHANGEAUTH
TPM2_InOut(ObjectChangeAuth);
#endif
// TPM Tests

/* ===========================================================================
 * GROUP A: Transport & Framing Negative Tests  (verification §1)
 * ===========================================================================
 */
#ifdef TPM_TEST_ENABLE_TRANSPORT_NEGATIVE
void TPM2_Transport_negative_tests(void) {
    DBG_PRINT("\n[TEST] Transport & framing negative tests\n");

    /* A1 — Invalid tag → TPM_RC_BAD_TAG */
    {
        GetRandom_In payload = {.bytesRequested = 4};
        tpm_rsp_header_t rsp =
            tpm_send_raw_command(0xFFFF, TPM_CC_GetRandom, &payload,
                                 sizeof(payload));
        assert(rsp.responseCode == TPM_RC_BAD_TAG,
               "Transport A1: invalid tag should return TPM_RC_BAD_TAG\n",
               string_from_TPM_RC(TPM_RC_BAD_TAG),
               string_from_TPM_RC(rsp.responseCode));
    }

    /* A2 — Unknown command code → TPM_RC_COMMAND_CODE */
    {
        uint8_t dummy = 0;
        tpm_rsp_header_t rsp =
            tpm_send_raw_command(TPM_ST_NO_SESSIONS, 0xDEADBEEF, &dummy,
                                 sizeof(dummy));
        assert(rsp.responseCode == TPM_RC_COMMAND_CODE,
               "Transport A2: unknown CC should return TPM_RC_COMMAND_CODE\n",
               string_from_TPM_RC(TPM_RC_COMMAND_CODE),
               string_from_TPM_RC(rsp.responseCode));
    }

    /* A3 — Short commandSize → TPM_RC_COMMAND_SIZE
     * Declare commandSize = header-only (no payload), but actually
     * send a Hash_In payload.  QEMU checks declared vs expected. */
    {
        Hash_In payload = {0};
        payload.hashAlg = TPM_ALG_SHA256;
        payload.data.size = 4;
        payload.data.buffer[0] = 'X';

        tpm_rsp_header_t rsp = tpm_send_raw_command_bad_size(
            TPM_ST_NO_SESSIONS, TPM_CC_Hash,
            (uint32_t)sizeof(tpm_cmd_header_t) + 1, /* too small */
            &payload, sizeof(payload));
        assert(rsp.responseCode == TPM_RC_COMMAND_SIZE,
               "Transport A3: short commandSize should return "
               "TPM_RC_COMMAND_SIZE\n",
               string_from_TPM_RC(TPM_RC_COMMAND_SIZE),
               string_from_TPM_RC(rsp.responseCode));
    }

    DBG_PRINT("[TEST] Transport negative tests: DONE\n");
}
#endif

#ifdef TPM_TEST_ENABLE_NV_DEFINE
void TPM2_NV_DefineSpace_test(void) {
    TPM_RC res;

    NV_DefineSpace_In test_input = {
        .authHandle = TPM_RH_OWNER,
        .auth = {.size = 0, // No authorization value (password) required for
                            // this example
                 .buffer = {0}},
        .publicInfo = {
            .size = 0,
            .nvPublic =
                {
                    .nvIndex = 0x01500016, // A valid index in the allowed range
                    .nameAlg = TPM_ALG_NULL,
                    .attributes = {.OWNERREAD = 1, .OWNERWRITE = 1},
                    .dataSize = 32, // The size of the NV space in bytes
                    .authPolicy = {.size =
                                       0, // No policy required for this example
                                   .buffer = {0}},
                },
        }};

    res = TPM2_NV_DefineSpace(&test_input);
    assert(res == TPM_RC_SUCCESS, "TPM2_NV_DefineSpace failed",
           string_from_TPM_RC(TPM_RC_SUCCESS), string_from_TPM_RC(res));
}
#endif

#ifdef TPM_TEST_ENABLE_NV_WRITE_READ
void TPM2_NV_WriteRead_test(void) {
    TPM_RC res;

    // Use previously defined nv_index
    const TPMI_RH_NV_INDEX nv_index = 0x01500016;
    const UINT16 data_size = 32;

    // --- 1. Write Data to NV Memory ---
    TPM2B_MAX_NV_BUFFER write_data = {
        .size = data_size,
        .buffer = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                   0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                   0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                   0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F}};

    NV_Write_In write_input = {
        .authHandle = TPM_RH_OWNER, // Authorize as Owner
        .nvIndex = nv_index,        // The index to write to
        .data = write_data,         // The data to write
        .offset = 0                 // Write at the beginning
    };

    res = TPM2_NV_Write(&write_input);
    assert(res == TPM_RC_SUCCESS, "TPM2_NV_Write failed",
           string_from_TPM_RC(TPM_RC_SUCCESS), string_from_TPM_RC(res));

    // --- 2. Read Data from NV Memory ---
    NV_Read_In read_input = {
        .authHandle = TPM_RH_OWNER, // Authorize as Owner
        .nvIndex = nv_index,        // The index to read from
        .size = data_size,          // Number of bytes to read
        .offset = 0                 // Read from the beginning
    };

    NV_Read_Out read_output = {0};

    res = TPM2_NV_Read(&read_input, &read_output);
    assert(res == TPM_RC_SUCCESS, "TPM2_NV_Read failed",
           string_from_TPM_RC(TPM_RC_SUCCESS), string_from_TPM_RC(res));

    // --- 3. Compare Actual Data with Expected ---
    char expected_size_str[12];
    char actual_size_str[12];
    snprintf(expected_size_str, sizeof(expected_size_str), "%u",
             write_data.size);
    snprintf(actual_size_str, sizeof(actual_size_str), "%u",
             read_output.data.size);
    assert(read_output.data.size == write_data.size, "NV Read size mismatch",
           expected_size_str, actual_size_str);

    assert(memcmp(read_output.data.buffer, write_data.buffer,
                  write_data.size) == 0,
           "NV Read data mismatch", NULL, NULL);
}
#endif

#ifdef TPM_TEST_ENABLE_HASH
void TPM2_Hash_smoke_test(void) {
    Hash_In in = {0};
    Hash_Out out = {0};
    in.hashAlg = TPM_ALG_SHA256;
    in.data.size = 4;
    in.data.buffer[0] = 'A';
    in.data.buffer[1] = 'B';
    in.data.buffer[2] = 'C';
    in.data.buffer[3] = 'D';

    TPM_RC res = TPM2_Hash(&in, &out);
    assert(res != TPM_RC_BAD_TAG, "TPM2_Hash bad tag", "!= TPM_RC_BAD_TAG",
           string_from_TPM_RC(res));
    assert(res != TPM_RC_COMMAND_SIZE, "TPM2_Hash command size",
           "!= TPM_RC_COMMAND_SIZE", string_from_TPM_RC(res));

    if (res == TPM_RC_SUCCESS) {
        assert(out.digest.size > 0, "TPM2_Hash digest size", "> 0", "0");
    }
}
#endif

#ifdef TPM_TEST_ENABLE_SIGN
void TPM2_Sign_smoke_test(void) {
    Sign_In in = {0};
    Sign_Out out = {0};

    in.keyHandle = 0x80000000;
    in.inScheme.scheme = TPM_ALG_NULL;
    in.inScheme.hashAlg = TPM_ALG_NULL;

    in.digest.size = 4;
    in.digest.buffer[0] = 'A';
    in.digest.buffer[1] = 'B';
    in.digest.buffer[2] = 'C';
    in.digest.buffer[3] = 'D';

    TPM_RC res = TPM2_Sign(&in, &out);
    assert(res != TPM_RC_BAD_TAG, "TPM2_Sign bad tag", "!= TPM_RC_BAD_TAG",
           string_from_TPM_RC(res));
    assert(res != TPM_RC_COMMAND_SIZE, "TPM2_Sign command size",
           "!= TPM_RC_COMMAND_SIZE", string_from_TPM_RC(res));

    if (res == TPM_RC_SUCCESS) {
        assert(out.signature.signature.size > 0, "TPM2_Sign signature size",
               "> 0", "0");
    }
}
#endif

#ifdef TPM_TEST_ENABLE_VERIFY_SIGNATURE
void TPM2_VerifySignature_smoke_test(void) {
    VerifySignature_In in = {0};
    VerifySignature_Out out = {0};

    in.keyHandle = 0x80000000;

    in.digest.size = 4;
    in.digest.buffer[0] = 'A';
    in.digest.buffer[1] = 'B';
    in.digest.buffer[2] = 'C';
    in.digest.buffer[3] = 'D';

    in.signature.signature.size = TPM_MAX_SIGNATURE_SIZE;
    for (int i = 0; i < TPM_MAX_SIGNATURE_SIZE; i++) {
        in.signature.signature.buffer[i] = (uint8_t)(0xA5u ^ (uint8_t)i);
    }

    TPM_RC res = TPM2_VerifySignature(&in, &out);
    assert(res != TPM_RC_BAD_TAG, "TPM2_VerifySignature bad tag",
           "!= TPM_RC_BAD_TAG", string_from_TPM_RC(res));
    assert(res != TPM_RC_COMMAND_SIZE, "TPM2_VerifySignature command size",
           "!= TPM_RC_COMMAND_SIZE", string_from_TPM_RC(res));

    (void)out;
}
#endif

#ifdef TPM_TEST_ENABLE_ENCRYPT_DECRYPT2
void TPM2_EncryptDecrypt2_smoke_test(void) {
    EncryptDecrypt2_In in = {0};
    EncryptDecrypt2_Out out = {0};

    in.keyHandle = 0x80000000;

    in.decrypt = 0;
    // Modified to match EncryptDecrypt2_In structure (no symDef, direct mode)
    in.mode = TPM_ALG_CBC;
    // Key bits/Alg determined by key handle

    in.ivIn.size = 16;
    for (int i = 0; i < 16; i++) {
        in.ivIn.buffer[i] = (uint8_t)i;
    }

    in.inData.size = 16;
    for (int i = 0; i < 16; i++) {
        in.inData.buffer[i] = (uint8_t)('A' + i);
    }

    TPM_RC res = TPM2_EncryptDecrypt2(&in, &out);
    assert(res != TPM_RC_BAD_TAG, "TPM2_EncryptDecrypt2 bad tag",
           "!= TPM_RC_BAD_TAG", string_from_TPM_RC(res));
    assert(res != TPM_RC_COMMAND_SIZE, "TPM2_EncryptDecrypt2 command size",
           "!= TPM_RC_COMMAND_SIZE", string_from_TPM_RC(res));

    if (res == TPM_RC_SUCCESS) {
        char expected_size_str[12];
        char actual_size_str[12];
        snprintf(expected_size_str, sizeof(expected_size_str), "%u",
                 in.inData.size);
        snprintf(actual_size_str, sizeof(actual_size_str), "%u",
                 out.outData.size);
        assert(out.outData.size == in.inData.size,
               "EncryptDecrypt2 size mismatch", expected_size_str,
               actual_size_str);
    }
}
#endif

#ifdef TPM_TEST_ENABLE_RSA_ENCRYPT_DECRYPT
void TPM2_RSA_EncryptDecrypt_smoke_test(void) {
    RSA_Encrypt_In enc_in = {0};
    RSA_Encrypt_Out enc_out = {0};

    enc_in.keyHandle = 0x80000000;
    enc_in.message.size = 4;
    enc_in.message.buffer[0] = 'A';
    enc_in.message.buffer[1] = 'B';
    enc_in.message.buffer[2] = 'C';
    enc_in.message.buffer[3] = 'D';

    TPM_RC res = TPM2_RSA_Encrypt(&enc_in, &enc_out);
    assert(res != TPM_RC_BAD_TAG, "TPM2_RSA_Encrypt bad tag",
           "!= TPM_RC_BAD_TAG", string_from_TPM_RC(res));
    assert(res != TPM_RC_COMMAND_SIZE, "TPM2_RSA_Encrypt command size",
           "!= TPM_RC_COMMAND_SIZE", string_from_TPM_RC(res));

    RSA_Decrypt_In dec_in = {0};
    RSA_Decrypt_Out dec_out = {0};

    dec_in.keyHandle = 0x80000000;
    dec_in.encrypted.size = 4;
    dec_in.encrypted.buffer[0] = 0x11;
    dec_in.encrypted.buffer[1] = 0x22;
    dec_in.encrypted.buffer[2] = 0x33;
    dec_in.encrypted.buffer[3] = 0x44;

    res = TPM2_RSA_Decrypt(&dec_in, &dec_out);
    assert(res != TPM_RC_BAD_TAG, "TPM2_RSA_Decrypt bad tag",
           "!= TPM_RC_BAD_TAG", string_from_TPM_RC(res));
    assert(res != TPM_RC_COMMAND_SIZE, "TPM2_RSA_Decrypt command size",
           "!= TPM_RC_COMMAND_SIZE", string_from_TPM_RC(res));

    (void)enc_out;
    (void)dec_out;
}
#endif

/*
 * ===========================================================================
 * KEY MANAGEMENT TESTS
 * ===========================================================================
 *
 * Test suite for TPM2 Key Management commands:
 * - TPM2_CreatePrimary: Create a primary key in a hierarchy
 * - TPM2_Create: Create a new key object under a parent
 * - TPM2_Load: Load a key into the TPM
 * - TPM2_ReadPublic: Read public area of a loaded object
 * - TPM2_ObjectChangeAuth: Change authorization value of an object
 *
 * These tests use shared state to test the complete key lifecycle.
 * ===========================================================================
 */

/* Shared state for key management tests */
#ifdef TPM_TEST_ENABLE_CREATEPRIMARY
static CreatePrimary_Out
    g_create_primary_out; /* Output from TPM2_CreatePrimary */
#endif

#ifdef TPM_TEST_ENABLE_CREATE
static Create_Out g_create_out; /* Output from TPM2_Create */
#endif

#ifdef TPM_TEST_ENABLE_LOAD
static Load_Out g_load_out; /* Output from TPM2_Load */
#endif

static TPM_HANDLE g_parent_handle; /* Parent key handle (primary) */
static bool g_key_created = false; /* Flag: key was created successfully */
static bool g_key_loaded = false;  /* Flag: key was loaded successfully */

/**
 * @brief Test TPM2_CreatePrimary command
 *
 * PURPOSE: Verify that the TPM2_CreatePrimary command successfully creates
 *          a new primary key in the Owner hierarchy.
 *
 * PASS:
 *   - TPM_RC_SUCCESS returned
 *   - Name should match the expected value for the given template
 *   - Hash(creationData) == creationHash
 *   - creationTicket is valid
 *
 * FAIL:
 *   - Any TPM_RC other than SUCCESS
 *   - Name doesn't match expected value for template
 *   - Hash(creationData) != creationHash
 *   - Invalid creationTicket
 */
#ifdef TPM_TEST_ENABLE_CREATEPRIMARY
void TPM2_CreatePrimary_test(void) {
    // ----------------------------------------------------------------
    // 1. Prepare Data Structures
    // ----------------------------------------------------------------

    // A. The Hierarchy Auth (We need permission to use the Owner Hierarchy)
    // By default, Owner Auth is empty. We pass ESYS_TR_PASSWORD.

    // C. Sensitive Data (Input 3 - Password for NEW key)
    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0, // SAPI ignores this outer size on input usually, but good
                   // practice
        .sensitive = {.userAuth = {.size = 0}, // No password for the new key
                      .data = {.size = 0}}};

    // D. Public Template (Input 4 - The Key Definition)
    TPM2B_PUBLIC inPublic = {
        .size = 0, // SAPI will calculate this
        .publicArea = {
            .type = TPM_ALG_RSA,
            .nameAlg = TPM_ALG_SHA256,
            .objectAttributes = {.userWithAuth = 1,
                                 .restricted = 1,
                                 .decrypt = 1,
                                 .fixedTPM = 1,
                                 .fixedParent = 1,
                                 .sensitiveDataOrigin = 1},
            .authPolicy = {.size = 0},
            .parameters.rsaDetail = {.symmetric = {.algorithm = TPM_ALG_AES,
                                                   .keyBits.aes = 128,
                                                   .mode.sym = TPM_ALG_CFB},
                                     .scheme = {.scheme = TPM_ALG_NULL},
                                     .keyBits = 2048,
                                     .exponent = 0},
            .unique.rsa = {.size = 0}}};

    // D. Metadata structures (PCRs and outside info)
    TPM2B_DATA outsideInfo = {.size = 0};
    TPML_PCR_SELECTION creationPCR = {.count = 0};

    CreatePrimary_In in = {.primaryHandle = TPM_RH_OWNER, // Owner Hierarchy
                           .inSensitive = inSensitive,
                           .inPublic = inPublic,
                           .outsideInfo = outsideInfo,
                           .creationPCR = creationPCR};

    // ----------------------------------------------------------------
    // 2. Execute Command
    // ----------------------------------------------------------------

    TPM_RC res = TPM2_CreatePrimary(&in, &g_create_primary_out);

    // ----------------------------------------------------------------
    // 3. Validate Results
    // ----------------------------------------------------------------

    // ----------------------------------------------------------------
    // ASSERT TPM_RC_SUCCESS returned
    // ----------------------------------------------------------------

    assert(res == TPM_RC_SUCCESS, "TPM2_CreatePrimary failed",
           string_from_TPM_RC(TPM_RC_SUCCESS), string_from_TPM_RC(res));

    // ----------------------------------------------------------------
    // ASSERT Name should match the expected value for the given template
    // ----------------------------------------------------------------

    // Name = nameAlg_BE(2) || SHA256(marshaled TPMT_PUBLIC)

    // 1. Marshal the public area into canonical big-endian form
    uint8_t marshal_buf[sizeof(TPMT_PUBLIC)];
    uint16_t marshal_len = TPMT_PUBLIC_Marshal(
        &g_create_primary_out.outPublic.publicArea, marshal_buf);

    // 2. Hash the marshaled bytes
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, marshal_buf, marshal_len);
    uint8_t digest[32];
    SHA256_Final(digest, &ctx);

    // 3. Prepend NameAlg (00 0B) to get the final "Name"
    uint8_t expected_name[34];
    expected_name[0] =
        (uint8_t)(g_create_primary_out.outPublic.publicArea.nameAlg >> 8);
    expected_name[1] =
        (uint8_t)(g_create_primary_out.outPublic.publicArea.nameAlg & 0xFF);
    memcpy(&expected_name[2], digest, 32);

    // 4. Compare with TPM returned Name
    {
        char exp_s[8], act_s[8];
        snprintf(exp_s, sizeof(exp_s), "%u", (unsigned)sizeof(expected_name));
        snprintf(act_s, sizeof(act_s), "%u", g_create_primary_out.name.size);
        assert(g_create_primary_out.name.size == sizeof(expected_name),
               "TPM2_CreatePrimary Name size mismatch", exp_s, act_s);
    }
    assert(memcmp(g_create_primary_out.name.buffer, expected_name,
                  sizeof(expected_name)) == 0,
           "TPM2_CreatePrimary Name mismatch", NULL, NULL);

    // ----------------------------------------------------------------
    // ASSERT Hash(creationData) == creationHash
    // ----------------------------------------------------------------

    // 1. Hash the creationData returned by the TPM
    uint8_t calculated_creation_hash[32];
    SHA256_CTX creation_ctx;
    SHA256_Init(&creation_ctx);

    DBG_PRINTF("[DBG] CreatePrimary: creationData.size = %u\n",
               g_create_primary_out.creationData.size);
    DBG_PRINTF("[DBG] CreatePrimary: creationHash.size = %u\n",
               g_create_primary_out.creationHash.size);

    // We hash the buffer of creationData, which contains the marshaled
    // TPMS_CREATION_DATA
    SHA256_Update(&creation_ctx, g_create_primary_out.creationData.buffer,
                  g_create_primary_out.creationData.size);
    SHA256_Final(calculated_creation_hash, &creation_ctx);

    // 2. Compare calculated hash against the creationHash returned by the TPM
    {
        char exp_s[8], act_s[8];
        snprintf(exp_s, sizeof(exp_s), "32");
        snprintf(act_s, sizeof(act_s), "%u",
                 g_create_primary_out.creationHash.size);
        assert(g_create_primary_out.creationHash.size == 32,
               "TPM2_CreatePrimary creationHash size mismatch", exp_s, act_s);
    }

    assert(memcmp(g_create_primary_out.creationHash.buffer,
                  calculated_creation_hash, 32) == 0,
           "TPM2_CreatePrimary creationHash mismatch", NULL, NULL);

    // ----------------------------------------------------------------
    // ASSERT creationTicket is valid
    // ----------------------------------------------------------------

    // A valid ticket should have the tag TPM_ST_CREATION
    assert(g_create_primary_out.creationTicket.tag == TPM_ST_CREATION,
           "TPM2_CreatePrimary ticket tag invalid", "TPM_ST_CREATION", "OTHER");

    // The hierarchy in the ticket must match the hierarchy used to create the
    // object
    assert(g_create_primary_out.creationTicket.hierarchy == TPM_RH_OWNER,
           "TPM2_CreatePrimary ticket hierarchy mismatch", "TPM_RH_OWNER",
           "OTHER");

    // The digest in the ticket must be non-zero (it's the HMAC/Signature)
    assert(g_create_primary_out.creationTicket.digest.size > 0,
           "TPM2_CreatePrimary ticket digest is empty", NULL, NULL);
}
#endif

#ifdef TPM_TEST_ENABLE_CREATEPRIMARY
/**
 * @brief Test TPM2_CreatePrimary with TPM_ST_SESSIONS (spec compliance test)
 *
 * PURPOSE: Verify that the TPM2_CreatePrimary command works with
 *          TPM_ST_SESSIONS tag and password authorization.
 *
 * PASS:
 *   - TPM_RC_SUCCESS returned
 *   - Response tag is TPM_ST_SESSIONS (0x8002)
 *   - Object handle is in transient range (0x80XXXXXX)
 *   - Name is present and valid
 *
 * FAIL:
 *   - Any TPM_RC other than SUCCESS
 *   - Response tag is not TPM_ST_SESSIONS
 *   - Invalid object handle or name
 */
void TPM2_CreatePrimary_with_sessions_test(void) {
    DBG_PRINT("\n=== TPM2_CreatePrimary with TPM_ST_SESSIONS Test ===\n");

    /* ----------------------------------------------------------------
     * 1. Prepare Data Structures (same as regular CreatePrimary test)
     * ---------------------------------------------------------------- */

    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0, .sensitive = {.userAuth = {.size = 0}, .data = {.size = 0}}};

    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM_ALG_RSA,
            .nameAlg = TPM_ALG_SHA256,
            .objectAttributes = {.userWithAuth = 1,
                                 .restricted = 1,
                                 .decrypt = 1,
                                 .fixedTPM = 1,
                                 .fixedParent = 1,
                                 .sensitiveDataOrigin = 1},
            .authPolicy = {.size = 0},
            .parameters.rsaDetail = {.symmetric = {.algorithm = TPM_ALG_AES,
                                                   .keyBits.aes = 128,
                                                   .mode.sym = TPM_ALG_CFB},
                                     .scheme = {.scheme = TPM_ALG_NULL},
                                     .keyBits = 2048,
                                     .exponent = 0},
            .unique.rsa = {.size = 0}}};

    TPM2B_DATA outsideInfo = {.size = 0};
    TPML_PCR_SELECTION creationPCR = {.count = 0};

    CreatePrimary_In in = {.primaryHandle = TPM_RH_OWNER,
                           .inSensitive = inSensitive,
                           .inPublic = inPublic,
                           .outsideInfo = outsideInfo,
                           .creationPCR = creationPCR};

    CreatePrimary_Out out;
    memset(&out, 0, sizeof(out));

    /* ----------------------------------------------------------------
     * 2. Send Command with TPM_ST_SESSIONS
     * ---------------------------------------------------------------- */

    tpm_cmd_header_t cmd = {.tag = TPM_ST_SESSIONS,
                            .commandSize =
                                sizeof(cmd) + sizeof(in) + AUTH_CMD_AREA_SIZE,
                            .commandCode = TPM_CC_CreatePrimary};

    DBG_PRINTF("[DBG] TPM2_CreatePrimary_sessions: Sending cmd (tag=0x%04X, "
               "size=%lu, code=0x%08lX)\n",
               cmd.tag, (unsigned long)cmd.commandSize,
               (unsigned long)cmd.commandCode);

    tpm_command_ready();
    tpm_send(&cmd, sizeof(cmd));
    tpm_send(&in, sizeof(in));
    tpm_send_auth_area(); /* Send password session area */
    tpm_go();

    /* ----------------------------------------------------------------
     * 3. Receive Response
     * ---------------------------------------------------------------- */

    tpm_rsp_header_t rsp;
    tpm_receive(&rsp, sizeof(rsp));

    DBG_PRINTF("[DBG] TPM2_CreatePrimary_sessions: Received rsp (tag=0x%04X, "
               "size=%lu, rc=0x%08lX)\n",
               rsp.tag, (unsigned long)rsp.responseSize,
               (unsigned long)rsp.responseCode);

    /* ----------------------------------------------------------------
     * 4. Validate Response
     * ---------------------------------------------------------------- */

    /* ASSERT: Command succeeded */
    assert(rsp.responseCode == TPM_RC_SUCCESS,
           "TPM2_CreatePrimary with sessions failed",
           string_from_TPM_RC(TPM_RC_SUCCESS),
           string_from_TPM_RC(rsp.responseCode));

    if (rsp.responseCode != TPM_RC_SUCCESS) {
        /* Drain remaining bytes and return */
        size_t remaining = (rsp.responseSize > sizeof(rsp)) ?
                               (size_t)rsp.responseSize - sizeof(rsp) :
                               0;
        tpm_drain_bytes(remaining);
        return;
    }

    /* ASSERT: Response tag is TPM_ST_SESSIONS */
    {
        char exp_str[8], act_str[8];
        snprintf(exp_str, sizeof(exp_str), "0x%04X", TPM_ST_SESSIONS);
        snprintf(act_str, sizeof(act_str), "0x%04X", rsp.tag);
        assert(rsp.tag == TPM_ST_SESSIONS,
               "Expected TPM_ST_SESSIONS response tag", exp_str, act_str);
    }

    /* Skip auth response area */
    skip_auth_response_area();

    /* Read output */
    tpm_receive(&out, sizeof(out));

    /* Drain any remaining bytes */
    size_t remaining =
        (rsp.responseSize > sizeof(rsp) + AUTH_RSP_AREA_SIZE + sizeof(out)) ?
            (size_t)rsp.responseSize - sizeof(rsp) - AUTH_RSP_AREA_SIZE -
                sizeof(out) :
            0;
    tpm_drain_bytes(remaining);

    /* ----------------------------------------------------------------
     * 5. Validate Output
     * ---------------------------------------------------------------- */

    /* ASSERT: Object handle is in transient range */
    {
        uint8_t ht = (uint8_t)(out.objectHandle >> HR_SHIFT);
        char exp_str[16], act_str[16];
        snprintf(exp_str, sizeof(exp_str), "0x80");
        snprintf(act_str, sizeof(act_str), "0x%02X", ht);
        assert(ht == 0x80,
               "TPM2_CreatePrimary_sessions: handle not in transient range",
               exp_str, act_str);
    }

    /* ASSERT: Name is present */
    assert(out.name.size > 0, "TPM2_CreatePrimary_sessions: name is empty",
           "> 0", "0");

    DBG_PRINT("[TEST] TPM2_CreatePrimary with TPM_ST_SESSIONS: SUCCESS\n");
    DBG_PRINTF("  Object handle: 0x%08lX\n", (unsigned long)out.objectHandle);
    DBG_PRINTF("  Name size: %u\n", out.name.size);
}
#endif

/**
 * @brief Test TPM2_Create command
 *
 * PURPOSE: Verify that the TPM2_Create command successfully creates a new
 *          RSA signing key under the primary (storage) key created by
 *          TPM2_CreatePrimary.
 *
 * PASS:
 *   - TPM_RC_SUCCESS returned
 *   - outPrivate.size > 0 (encrypted private portion generated)
 *   - outPublic.size  > 0 (public portion generated)
 *   - Hash(creationData) == creationHash
 *   - creationTicket tag == TPM_ST_CREATION
 *
 * FAIL:
 *   - Any TPM_RC other than SUCCESS
 *   - TPM_RC_BAD_TAG or TPM_RC_COMMAND_SIZE (marshalling errors)
 *   - Empty outputs (size == 0)
 *   - creationHash mismatch
 */
#ifdef TPM_TEST_ENABLE_CREATE
void TPM2_Create_test(void) {
    TPM_RC res;

    DBG_PRINT("[TEST] TPM2_Create: Creating RSA signing key under primary\n");

    /* Use the primary key handle from TPM2_CreatePrimary test */
    g_parent_handle = g_create_primary_out.objectHandle;
    DBG_PRINTF("[TEST] TPM2_Create: parent handle = 0x%08lX\n",
               (unsigned long)g_parent_handle);

    Create_In in = {0};
    memset(&g_create_out, 0, sizeof(g_create_out));

    /* ---- Parent handle ---- */
    in.parentHandle = g_parent_handle;

    /* ---- Sensitive: empty auth & no injected data ---- */
    in.inSensitive.size = 0;
    in.inSensitive.sensitive.userAuth.size = 0;
    in.inSensitive.sensitive.data.size = 0;

    /* ---- Public template: RSA-2048 signing key (unrestricted) ---- */
    in.inPublic.size = 0; /* TPM/marshaller will compute */
    in.inPublic.publicArea.type = TPM_ALG_RSA;
    in.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;

    in.inPublic.publicArea.objectAttributes.fixedTPM = 1;
    in.inPublic.publicArea.objectAttributes.fixedParent = 1;
    in.inPublic.publicArea.objectAttributes.sensitiveDataOrigin = 1;
    in.inPublic.publicArea.objectAttributes.userWithAuth = 1;
    in.inPublic.publicArea.objectAttributes.sign_encrypt = 1;
    /* NOT restricted, NOT decrypt => unrestricted signing key */

    in.inPublic.publicArea.authPolicy.size = 0;

    /* No inner symmetric protection (signing key, not storage key) */
    in.inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm =
        TPM_ALG_NULL;
    in.inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_RSASSA;
    in.inPublic.publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg =
        TPM_ALG_SHA256;
    in.inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
    in.inPublic.publicArea.parameters.rsaDetail.exponent =
        0; /* default 65537 */

    in.inPublic.publicArea.unique.rsa.size = 0; /* TPM generates */

    /* ---- No outside info / PCR ---- */
    in.outsideInfo.size = 0;
    in.creationPCR.count = 0;

    /* ---- Execute command ---- */
    res = TPM2_Create(&in, &g_create_out);

    /* ---- Marshalling sanity ---- */
    assert(res != TPM_RC_BAD_TAG, "TPM2_Create failed: bad tag\n",
           "!= TPM_RC_BAD_TAG", string_from_TPM_RC(res));
    assert(res != TPM_RC_COMMAND_SIZE, "TPM2_Create failed: command size\n",
           "!= TPM_RC_COMMAND_SIZE", string_from_TPM_RC(res));

    /* ---- Result validation ---- */
    assert(res == TPM_RC_SUCCESS, "TPM2_Create: command failed\n",
           string_from_TPM_RC(TPM_RC_SUCCESS), string_from_TPM_RC(res));

    if (res == TPM_RC_SUCCESS) {
        g_key_created = true;

        /* Private portion must be present (encrypted blob) */
        assert(g_create_out.outPrivate.size > 0,
               "TPM2_Create: outPrivate is empty\n", "> 0", "0");

        /* Public portion must be present */
        assert(g_create_out.outPublic.size > 0,
               "TPM2_Create: outPublic is empty\n", "> 0", "0");

        /* ---- Hash(creationData) == creationHash ---- */
        uint8_t calc_hash[32];
        SHA256_CTX hash_ctx;
        SHA256_Init(&hash_ctx);
        SHA256_Update(&hash_ctx, g_create_out.creationData.buffer,
                      g_create_out.creationData.size);
        SHA256_Final(calc_hash, &hash_ctx);

        assert(g_create_out.creationHash.size == 32,
               "TPM2_Create: creationHash size != 32\n", "32", "other");
        assert(memcmp(g_create_out.creationHash.buffer, calc_hash, 32) == 0,
               "TPM2_Create: creationHash mismatch\n", NULL, NULL);

        /* ---- creationTicket tag ---- */
        assert(g_create_out.creationTicket.tag == TPM_ST_CREATION,
               "TPM2_Create: ticket tag invalid\n", "TPM_ST_CREATION", "OTHER");

        DBG_PRINTF(
            "[TEST] TPM2_Create: SUCCESS (private=%u, public=%u bytes)\n",
            g_create_out.outPrivate.size, g_create_out.outPublic.size);
    } else {
        DBG_PRINTF("[TEST] TPM2_Create: FAILED with rc=0x%08lX (%s)\n",
                   (unsigned long)res, string_from_TPM_RC(res));
    }
}
#endif

/**
 * @brief Test TPM2_Load command
 *
 * PURPOSE: Verify that a key created with TPM2_Create can be loaded
 *          into the TPM for use.
 *
 * PREREQUISITE: TPM2_Create_test must have passed (g_key_created == true)
 *
 * PASS:
 *   - TPM_RC_SUCCESS returned
 *   - objectHandle is in the transient range (0x80XXXXXX)
 *   - name.size > 0 (object name computed)
 *   - Name == nameAlg || Hash(publicArea)   (computed from outPublic)
 *
 * FAIL:
 *   - Any TPM_RC other than SUCCESS
 *   - Handle outside transient range
 *   - Empty name
 *   - Name mismatch with calculated value
 */
#ifdef TPM_TEST_ENABLE_LOAD
void TPM2_Load_test(void) {
    TPM_RC res;

    DBG_PRINT("[TEST] TPM2_Load: Loading created key into TPM\n");

    /* Skip if Create failed */
    if (!g_key_created) {
        DBG_PRINT("[TEST] TPM2_Load: SKIPPED (Create failed)\n");
        assert(false, "TPM2_Load: SKIPPED because Create failed\n",
               "g_key_created==true", "false");
        return;
    }

    Load_In in = {0};
    memset(&g_load_out, 0, sizeof(g_load_out));

    /* Use the parent handle from Create */
    in.parentHandle = g_parent_handle;

    /* Use the private/public portions from Create output */
    memcpy(&in.inPrivate, &g_create_out.outPrivate, sizeof(in.inPrivate));
    memcpy(&in.inPublic, &g_create_out.outPublic, sizeof(in.inPublic));

    DBG_PRINTF("[TEST] TPM2_Load: parent=0x%08lX, private=%u, public=%u\n",
               (unsigned long)in.parentHandle, in.inPrivate.size,
               in.inPublic.size);

    /* ---- Execute command ---- */
    res = TPM2_Load(&in, &g_load_out);

    /* ---- Marshalling sanity ---- */
    assert(res != TPM_RC_BAD_TAG, "TPM2_Load failed: bad tag\n",
           "!= TPM_RC_BAD_TAG", string_from_TPM_RC(res));
    assert(res != TPM_RC_COMMAND_SIZE, "TPM2_Load failed: command size\n",
           "!= TPM_RC_COMMAND_SIZE", string_from_TPM_RC(res));

    /* ---- Must succeed ---- */
    assert(res == TPM_RC_SUCCESS, "TPM2_Load: command failed\n",
           string_from_TPM_RC(TPM_RC_SUCCESS), string_from_TPM_RC(res));

    if (res != TPM_RC_SUCCESS) {
        DBG_PRINTF("[TEST] TPM2_Load: FAILED with rc=0x%08lX (%s)\n",
                   (unsigned long)res, string_from_TPM_RC(res));
        return;
    }

    g_key_loaded = true;

    /* ================================================================
     * ASSERT 1: objectHandle is in transient object range (0x80XXXXXX)
     * TPM_HT_TRANSIENT = 0x80, shifted by HR_SHIFT (24) => 0x80000000
     * ================================================================ */
    {
        uint8_t ht = (uint8_t)(g_load_out.objectHandle >> HR_SHIFT);
        char exp_str[16], act_str[16];
        snprintf(exp_str, sizeof(exp_str), "0x80");
        snprintf(act_str, sizeof(act_str), "0x%02X", ht);
        assert(ht == 0x80, "TPM2_Load: handle not in transient range\n",
               exp_str, act_str);
    }

    /* ================================================================
     * ASSERT 2: objectHandle != 0 and != TPM_RH_UNASSIGNED
     * ================================================================ */
    {
        char handle_str[16];
        snprintf(handle_str, sizeof(handle_str), "0x%08lX",
                 (unsigned long)g_load_out.objectHandle);
        assert(g_load_out.objectHandle != 0,
               "TPM2_Load: objectHandle is zero\n", "!= 0", handle_str);
        assert(g_load_out.objectHandle != TPM_RH_UNASSIGNED,
               "TPM2_Load: objectHandle is UNASSIGNED\n",
               "!= TPM_RH_UNASSIGNED", handle_str);
    }

    /* ================================================================
     * ASSERT 3: name.size > 0
     * ================================================================ */
    assert(g_load_out.name.size > 0, "TPM2_Load: name is empty\n", "> 0", "0");

    /* ================================================================
     * ASSERT 4: Name == nameAlg || Hash(TPMT_PUBLIC)
     *
     * The Name of a loaded object is computed as:
     *   Name = nameAlg (2 bytes, big-endian) || Hash_nameAlg(publicArea)
     *
     * QEMU uses proper big-endian marshaling of TPMT_PUBLIC.
     * We must do the same on the firmware side.
     * ================================================================ */
    {
        TPMT_PUBLIC *pub = &g_create_out.outPublic.publicArea;

        /* Marshal then hash */
        uint8_t load_marshal_buf[sizeof(TPMT_PUBLIC)];
        uint16_t load_marshal_len = TPMT_PUBLIC_Marshal(pub, load_marshal_buf);
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, load_marshal_buf, load_marshal_len);

        uint8_t load_digest[32];
        SHA256_Final(load_digest, &ctx);

        /* Build expected Name = nameAlg_BE || digest */
        uint8_t expected_name[34];
        expected_name[0] = (uint8_t)(pub->nameAlg >> 8);
        expected_name[1] = (uint8_t)(pub->nameAlg & 0xFF);
        memcpy(&expected_name[2], load_digest, 32);

        /* Compare sizes */
        {
            char exp_s[8], act_s[8];
            snprintf(exp_s, sizeof(exp_s), "%u",
                     (unsigned)sizeof(expected_name));
            snprintf(act_s, sizeof(act_s), "%u", g_load_out.name.size);
            assert(g_load_out.name.size == sizeof(expected_name),
                   "TPM2_Load: Name size mismatch\n", exp_s, act_s);
        }

        /* Compare content */
        assert(memcmp(g_load_out.name.buffer, expected_name,
                      sizeof(expected_name)) == 0,
               "TPM2_Load: Name content mismatch\n", NULL, NULL);
    }

    /* ================================================================
     * ASSERT 5: public area type matches what we requested
     * ================================================================ */
    assert(g_create_out.outPublic.publicArea.type == TPM_ALG_RSA,
           "TPM2_Load: loaded key type != RSA\n", "TPM_ALG_RSA", "OTHER");

    DBG_PRINTF("[TEST] TPM2_Load: SUCCESS (handle=0x%08lX, name_size=%u)\n",
               (unsigned long)g_load_out.objectHandle, g_load_out.name.size);
}

/**
 * @brief Negative tests for TPM2_Load
 *
 * PURPOSE: Verify that the TPM correctly rejects malformed Load inputs.
 *          Each sub-test copies valid Create output, corrupts one field,
 *          and asserts that TPM2_Load returns an appropriate error.
 *
 * PREREQUISITE: TPM2_Load_test must have passed (g_key_loaded == true)
 *
 * Properties verified:
 *   1B - Binding Validation (public/private mismatch)
 *   1A - Attribute Consistency (sign+encrypt both CLEAR)
 *   1A - Key Size Consistency (keyBits mismatch)
 *   1D - Zero-Length Private Area
 */
void TPM2_Load_negative_tests(void) {
    TPM_RC res;

    DBG_PRINT("\n[TEST] TPM2_Load negative tests\n");

    if (!g_key_loaded) {
        DBG_PRINT("[TEST] TPM2_Load negative: SKIPPED (Load not ready)\n");
        return;
    }

    /* ================================================================
     * 1B: Binding Validation — modify nameAlg in public area
     *
     * The inPrivate was encrypted for the original public template.
     * Changing nameAlg in inPublic creates a public/private mismatch.
     * Expected: non-success (typically TPM_RC_BINDING)
     * ================================================================ */
    {
        Load_In bad_in = {0};
        Load_Out bad_out = {0};
        bad_in.parentHandle = g_parent_handle;
        memcpy(&bad_in.inPrivate, &g_create_out.outPrivate,
               sizeof(bad_in.inPrivate));
        memcpy(&bad_in.inPublic, &g_create_out.outPublic,
               sizeof(bad_in.inPublic));

        /* Corrupt: change nameAlg from SHA256 to SHA1 */
        bad_in.inPublic.publicArea.nameAlg = TPM_ALG_SHA1;

        res = TPM2_Load(&bad_in, &bad_out);
        assert(res != TPM_RC_SUCCESS,
               "TPM2_Load negative (binding): should have failed\n",
               "!= TPM_RC_SUCCESS", string_from_TPM_RC(res));
        DBG_PRINTF("[TEST] TPM2_Load negative (binding): rc=0x%08lX (%s)\n",
                   (unsigned long)res, string_from_TPM_RC(res));
    }

    /* ================================================================
     * 1A: Attribute Consistency — clear both sign and decrypt
     *
     * For a non-keyedHash object, at least one of sign_encrypt or
     * decrypt must be SET. Clearing both should yield TPM_RC_ATTRIBUTES.
     * ================================================================ */
    {
        Load_In bad_in = {0};
        Load_Out bad_out = {0};
        bad_in.parentHandle = g_parent_handle;
        memcpy(&bad_in.inPrivate, &g_create_out.outPrivate,
               sizeof(bad_in.inPrivate));
        memcpy(&bad_in.inPublic, &g_create_out.outPublic,
               sizeof(bad_in.inPublic));

        /* Corrupt: clear both sign_encrypt and decrypt */
        bad_in.inPublic.publicArea.objectAttributes.sign_encrypt = 0;
        bad_in.inPublic.publicArea.objectAttributes.decrypt = 0;

        res = TPM2_Load(&bad_in, &bad_out);
        assert(res != TPM_RC_SUCCESS,
               "TPM2_Load negative (attributes): should have failed\n",
               "!= TPM_RC_SUCCESS", string_from_TPM_RC(res));
        DBG_PRINTF("[TEST] TPM2_Load negative (attributes): rc=0x%08lX (%s)\n",
                   (unsigned long)res, string_from_TPM_RC(res));
    }

    /* ================================================================
     * 1A: Key Size Consistency — change keyBits to wrong value
     *
     * The private portion was created for 2048-bit RSA. Claiming
     * 1024-bit in the public area should be rejected.
     * ================================================================ */
    {
        Load_In bad_in = {0};
        Load_Out bad_out = {0};
        bad_in.parentHandle = g_parent_handle;
        memcpy(&bad_in.inPrivate, &g_create_out.outPrivate,
               sizeof(bad_in.inPrivate));
        memcpy(&bad_in.inPublic, &g_create_out.outPublic,
               sizeof(bad_in.inPublic));

        /* Corrupt: change keyBits from 2048 to 1024 */
        bad_in.inPublic.publicArea.parameters.rsaDetail.keyBits = 1024;

        res = TPM2_Load(&bad_in, &bad_out);
        assert(res != TPM_RC_SUCCESS,
               "TPM2_Load negative (key size): should have failed\n",
               "!= TPM_RC_SUCCESS", string_from_TPM_RC(res));
        DBG_PRINTF("[TEST] TPM2_Load negative (key size): rc=0x%08lX (%s)\n",
                   (unsigned long)res, string_from_TPM_RC(res));
    }

    /* ================================================================
     * 1D: Zero-Length Private Area
     *
     * A Load with an empty private area should always fail.
     * ================================================================ */
    {
        Load_In bad_in = {0};
        Load_Out bad_out = {0};
        bad_in.parentHandle = g_parent_handle;
        memcpy(&bad_in.inPublic, &g_create_out.outPublic,
               sizeof(bad_in.inPublic));

        /* Corrupt: zero-length private */
        bad_in.inPrivate.size = 0;
        memset(bad_in.inPrivate.buffer, 0, sizeof(bad_in.inPrivate.buffer));

        res = TPM2_Load(&bad_in, &bad_out);
        assert(res != TPM_RC_SUCCESS,
               "TPM2_Load negative (zero private): should have failed\n",
               "!= TPM_RC_SUCCESS", string_from_TPM_RC(res));
        DBG_PRINTF(
            "[TEST] TPM2_Load negative (zero private): rc=0x%08lX (%s)\n",
            (unsigned long)res, string_from_TPM_RC(res));
    }

    DBG_PRINT("[TEST] TPM2_Load negative tests: DONE\n");
}
#endif

/**
 * @brief Test TPM2_ReadPublic command
 *
 * PURPOSE: Verify that the public area of a loaded key can be read
 *          and that the data is consistent with what was created.
 *
 * PREREQUISITE: TPM2_Load_test must have passed (g_key_loaded == true)
 *
 * PASS:
 *   - TPM_RC_SUCCESS returned
 *   - outPublic.dataSize > 0 (public area not empty)
 *   - name.size > 0 (name present)
 *   - qualifiedName.size > 0 (qualified name present)
 *
 * FAIL:
 *   - Any TPM_RC other than SUCCESS
 *   - Empty outputs
 */
#ifdef TPM_TEST_ENABLE_READPUBLIC
void TPM2_ReadPublic_test(void) {
    TPM_RC res;

    DBG_PRINT("[TEST] TPM2_ReadPublic: Reading public area of loaded key\n");

    /* Skip if Load failed */
    if (!g_key_loaded) {
        DBG_PRINT("[TEST] TPM2_ReadPublic: SKIPPED (Load failed)\n");
        return;
    }

    ReadPublic_In in = {0};
    ReadPublic_Out out = {0};

    /* Read the public area of the loaded object */
    in.objectHandle = g_load_out.objectHandle;

    res = TPM2_ReadPublic(&in, &out);

    /* Check for marshalling errors */
    assert(res != TPM_RC_BAD_TAG, "TPM2_ReadPublic failed: bad tag\n",
           "!= TPM_RC_BAD_TAG", string_from_TPM_RC(res));

    assert(res != TPM_RC_COMMAND_SIZE, "TPM2_ReadPublic failed: command size\n",
           "!= TPM_RC_COMMAND_SIZE", string_from_TPM_RC(res));

    if (res == TPM_RC_SUCCESS) {
        /* Verify public area is present */
        assert(out.outPublic.size > 0, "TPM2_ReadPublic: outPublic is empty\n",
               "> 0", "0");

        /* Verify name is present */
        assert(out.name.size > 0, "TPM2_ReadPublic: name is empty\n", "> 0",
               "0");

        /* Verify qualified name is present */
        assert(out.qualifiedName.size > 0,
               "TPM2_ReadPublic: qualifiedName is empty\n", "> 0", "0");

        /* Verify name matches what was returned by Load */
        assert(out.name.size == g_load_out.name.size,
               "TPM2_ReadPublic: name size mismatch with Load output\n", NULL,
               NULL);

        if (out.name.size == g_load_out.name.size) {
            assert(memcmp(out.name.buffer, g_load_out.name.buffer,
                          out.name.size) == 0,
                   "TPM2_ReadPublic: name content mismatch with Load output\n",
                   NULL, NULL);
        }

        /* ================================================================
         * Property 2A: Public Area Match
         *
         * outPublic from ReadPublic must match the public area that was
         * originally created (g_create_out.outPublic). We marshal both
         * TPMT_PUBLIC structures to canonical form and compare bytes.
         * ================================================================ */
        {
            uint8_t rp_marshal[sizeof(TPMT_PUBLIC)];
            uint8_t cr_marshal[sizeof(TPMT_PUBLIC)];
            uint16_t rp_len =
                TPMT_PUBLIC_Marshal(&out.outPublic.publicArea, rp_marshal);
            uint16_t cr_len = TPMT_PUBLIC_Marshal(
                &g_create_out.outPublic.publicArea, cr_marshal);

            char exp_s[8], act_s[8];
            snprintf(exp_s, sizeof(exp_s), "%u", cr_len);
            snprintf(act_s, sizeof(act_s), "%u", rp_len);
            assert(rp_len == cr_len,
                   "TPM2_ReadPublic: public area marshaled size mismatch\n",
                   exp_s, act_s);

            if (rp_len == cr_len) {
                assert(memcmp(rp_marshal, cr_marshal, rp_len) == 0,
                       "TPM2_ReadPublic: public area content mismatch "
                       "with Create output\n",
                       NULL, NULL);
            }
        }

        /* ================================================================
         * Property 2D: Qualified Name Verification
         *
         * The qualified name must start with nameAlg (2 bytes, BE) and
         * be at least nameAlg_size + hash_size bytes long.
         * For SHA-256: >= 2 + 32 = 34 bytes.
         * ================================================================ */
        {
            char exp_s[8], act_s[8];
            snprintf(exp_s, sizeof(exp_s), ">= 34");
            snprintf(act_s, sizeof(act_s), "%u", out.qualifiedName.size);
            assert(out.qualifiedName.size >= 34,
                   "TPM2_ReadPublic: qualifiedName too short for SHA-256\n",
                   exp_s, act_s);

            /* First 2 bytes should be nameAlg in big-endian */
            uint8_t expected_alg_hi = (uint8_t)(TPM_ALG_SHA256 >> 8);
            uint8_t expected_alg_lo = (uint8_t)(TPM_ALG_SHA256 & 0xFF);
            char exp_alg[8], act_alg[8];
            snprintf(exp_alg, sizeof(exp_alg), "0x%02X%02X", expected_alg_hi,
                     expected_alg_lo);
            snprintf(act_alg, sizeof(act_alg), "0x%02X%02X",
                     out.qualifiedName.buffer[0], out.qualifiedName.buffer[1]);
            assert(out.qualifiedName.buffer[0] == expected_alg_hi &&
                       out.qualifiedName.buffer[1] == expected_alg_lo,
                   "TPM2_ReadPublic: qualifiedName nameAlg mismatch\n", exp_alg,
                   act_alg);
        }

        DBG_PRINTF("[TEST] TPM2_ReadPublic: SUCCESS (public=%u, name=%u, "
                   "qname=%u bytes)\n",
                   out.outPublic.size, out.name.size, out.qualifiedName.size);
    } else {
        DBG_PRINTF("[TEST] TPM2_ReadPublic: FAILED with rc=0x%08lX (%s)\n",
                   (unsigned long)res, string_from_TPM_RC(res));

        assert(res == TPM_RC_SUCCESS, "TPM2_ReadPublic: command failed\n",
               string_from_TPM_RC(TPM_RC_SUCCESS), string_from_TPM_RC(res));
    }
}
#endif

/**
 * @brief Test TPM2_ObjectChangeAuth command
 *
 * PURPOSE: Verify that the authorization value of an object can be
 *          changed correctly.
 *
 * PREREQUISITE: TPM2_Load_test must have passed (g_key_loaded == true)
 *
 * PASS:
 *   - TPM_RC_SUCCESS returned
 *   - outPrivate.dataSize > 0 (new private portion generated)
 *   - The new private portion differs from the original (auth changed)
 *
 * FAIL:
 *   - Any TPM_RC other than SUCCESS
 *   - Empty output
 */
#ifdef TPM_TEST_ENABLE_OBJECTCHANGEAUTH
void TPM2_ObjectChangeAuth_test(void) {
    TPM_RC res;

    DBG_PRINT(
        "[TEST] TPM2_ObjectChangeAuth: Changing auth value of loaded key\n");

    /* Skip if Load failed */
    if (!g_key_loaded) {
        DBG_PRINT("[TEST] TPM2_ObjectChangeAuth: SKIPPED (Load failed)\n");
        return;
    }

    ObjectChangeAuth_In in = {0};
    ObjectChangeAuth_Out out = {0};

    /* Configure input */
    in.objectHandle = g_load_out.objectHandle;
    in.parentHandle = g_parent_handle;

    /* New auth value - simple test value */
    in.newAuth.size = 8;
    in.newAuth.buffer[0] = 'N';
    in.newAuth.buffer[1] = 'E';
    in.newAuth.buffer[2] = 'W';
    in.newAuth.buffer[3] = 'A';
    in.newAuth.buffer[4] = 'U';
    in.newAuth.buffer[5] = 'T';
    in.newAuth.buffer[6] = 'H';
    in.newAuth.buffer[7] = '!';

    res = TPM2_ObjectChangeAuth(&in, &out);

    /* Check for marshalling errors */
    assert(res != TPM_RC_BAD_TAG, "TPM2_ObjectChangeAuth failed: bad tag\n",
           "!= TPM_RC_BAD_TAG", string_from_TPM_RC(res));

    assert(res != TPM_RC_COMMAND_SIZE,
           "TPM2_ObjectChangeAuth failed: command size\n",
           "!= TPM_RC_COMMAND_SIZE", string_from_TPM_RC(res));

    if (res == TPM_RC_SUCCESS) {
        /* Verify new private portion is present */
        assert(out.outPrivate.size > 0,
               "TPM2_ObjectChangeAuth: outPrivate is empty\n", "> 0", "0");

        /* Verify the new private portion is different from original
         * (this confirms the auth was actually changed) */
        bool is_different =
            (out.outPrivate.size != g_create_out.outPrivate.size);
        if (!is_different && out.outPrivate.size > 0) {
            is_different =
                (memcmp(out.outPrivate.buffer, g_create_out.outPrivate.buffer,
                        out.outPrivate.size) != 0);
        }

        assert(is_different,
               "TPM2_ObjectChangeAuth: outPrivate unchanged (auth may not have "
               "changed)\n",
               "different", "same");

        DBG_PRINTF(
            "[TEST] TPM2_ObjectChangeAuth: SUCCESS (new_private=%u bytes)\n",
            out.outPrivate.size);
    } else {
        DBG_PRINTF(
            "[TEST] TPM2_ObjectChangeAuth: FAILED with rc=0x%08lX (%s)\n",
            (unsigned long)res, string_from_TPM_RC(res));

        assert(res == TPM_RC_SUCCESS, "TPM2_ObjectChangeAuth: command failed\n",
               string_from_TPM_RC(TPM_RC_SUCCESS), string_from_TPM_RC(res));
    }
}
#endif

/* ===========================================================================
 * GROUP B: CreatePrimary Template Match  (verification §3)
 * ===========================================================================
 */
#if defined(TPM_TEST_ENABLE_CREATEPRIMARY_TEMPLATE_MATCH) && \
    defined(TPM_TEST_ENABLE_CREATEPRIMARY)
void TPM2_CreatePrimary_template_match_test(void) {
    DBG_PRINT("\n[TEST] CreatePrimary template match verification\n");

    TPMT_PUBLIC *pub = &g_create_primary_out.outPublic.publicArea;

    /* type == RSA */
    assert(pub->type == TPM_ALG_RSA,
           "Template match: type != TPM_ALG_RSA\n", "TPM_ALG_RSA", "OTHER");

    /* nameAlg == SHA-256 */
    {
        char exp[8], act[8];
        snprintf(exp, sizeof(exp), "0x%04X", TPM_ALG_SHA256);
        snprintf(act, sizeof(act), "0x%04X", pub->nameAlg);
        assert(pub->nameAlg == TPM_ALG_SHA256,
               "Template match: nameAlg != SHA256\n", exp, act);
    }

    /* objectAttributes */
    assert(pub->objectAttributes.restricted == 1,
           "Template match: restricted != 1\n", "1", "0");
    assert(pub->objectAttributes.decrypt == 1,
           "Template match: decrypt != 1\n", "1", "0");
    assert(pub->objectAttributes.fixedTPM == 1,
           "Template match: fixedTPM != 1\n", "1", "0");
    assert(pub->objectAttributes.fixedParent == 1,
           "Template match: fixedParent != 1\n", "1", "0");
    assert(pub->objectAttributes.sensitiveDataOrigin == 1,
           "Template match: sensitiveDataOrigin != 1\n", "1", "0");
    assert(pub->objectAttributes.userWithAuth == 1,
           "Template match: userWithAuth != 1\n", "1", "0");

    /* RSA key bits == 2048 */
    {
        char exp[8], act[8];
        snprintf(exp, sizeof(exp), "2048");
        snprintf(act, sizeof(act), "%u", pub->parameters.rsaDetail.keyBits);
        assert(pub->parameters.rsaDetail.keyBits == 2048,
               "Template match: keyBits != 2048\n", exp, act);
    }

    /* symmetric algorithm == AES */
    assert(pub->parameters.rsaDetail.symmetric.algorithm == TPM_ALG_AES,
           "Template match: symmetric != AES\n", "TPM_ALG_AES", "OTHER");

    DBG_PRINT("[TEST] CreatePrimary template match: DONE\n");
}
#endif

/* ===========================================================================
 * GROUP C: Create Negative Tests  (verification §4)
 * ===========================================================================
 */
#if defined(TPM_TEST_ENABLE_CREATE_NEGATIVE) && \
    defined(TPM_TEST_ENABLE_CREATEPRIMARY)
void TPM2_Create_negative_tests(void) {
    TPM_RC res;

    DBG_PRINT("\n[TEST] Create negative tests\n");

    /* C1 — Invalid parent handle */
    {
        Create_In bad_in = {0};
        Create_Out bad_out = {0};
        bad_in.parentHandle = 0xDEADBEEF;
        bad_in.inPublic.publicArea.type = TPM_ALG_RSA;
        bad_in.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
        bad_in.inPublic.publicArea.objectAttributes.sign_encrypt = 1;
        bad_in.inPublic.publicArea.objectAttributes.sensitiveDataOrigin = 1;
        bad_in.inPublic.publicArea.objectAttributes.userWithAuth = 1;
        bad_in.inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
        bad_in.inPublic.publicArea.parameters.rsaDetail.scheme.scheme =
            TPM_ALG_NULL;

        res = TPM2_Create(&bad_in, &bad_out);
        assert(res != TPM_RC_SUCCESS,
               "Create C1: invalid parentHandle should fail\n",
               "!= TPM_RC_SUCCESS", string_from_TPM_RC(res));
        DBG_PRINTF("[TEST] Create C1 (bad parent): rc=0x%08lX (%s)\n",
                   (unsigned long)res, string_from_TPM_RC(res));
    }

    /* C2 — nameAlg = TPM_ALG_NULL → should return error (TPM_RC_HASH) */
    {
        Create_In bad_in = {0};
        Create_Out bad_out = {0};
        bad_in.parentHandle = g_create_primary_out.objectHandle;
        bad_in.inPublic.publicArea.type = TPM_ALG_RSA;
        bad_in.inPublic.publicArea.nameAlg = TPM_ALG_NULL;
        bad_in.inPublic.publicArea.objectAttributes.sign_encrypt = 1;
        bad_in.inPublic.publicArea.objectAttributes.sensitiveDataOrigin = 1;
        bad_in.inPublic.publicArea.objectAttributes.userWithAuth = 1;
        bad_in.inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;

        res = TPM2_Create(&bad_in, &bad_out);
        assert(res != TPM_RC_SUCCESS,
               "Create C2: nameAlg=NULL should fail\n",
               "!= TPM_RC_SUCCESS", string_from_TPM_RC(res));
        DBG_PRINTF("[TEST] Create C2 (null nameAlg): rc=0x%08lX (%s)\n",
                   (unsigned long)res, string_from_TPM_RC(res));
    }

    DBG_PRINT("[TEST] Create negative tests: DONE\n");
}
#endif

/* ===========================================================================
 * GROUP D: Load Private Blob Integrity  (verification §5)
 * ===========================================================================
 */
#if defined(TPM_TEST_ENABLE_LOAD_PRIVATE_INTEGRITY) && \
    defined(TPM_TEST_ENABLE_CREATE) && defined(TPM_TEST_ENABLE_LOAD)
void TPM2_Load_private_integrity_test(void) {
    TPM_RC res;

    DBG_PRINT("\n[TEST] Load private blob integrity test\n");

    if (!g_key_created) {
        DBG_PRINT("[TEST] Load integrity: SKIPPED (Create failed)\n");
        return;
    }

    /* Flip a byte in the middle of the private blob (inside the
     * TPMT_SENSITIVE region, before the integrity digest).
     * PrivateToSensitive() in QEMU recomputes SHA256(Name || sensitive)
     * and compares against the stored digest — this must mismatch. */
    {
        Load_In bad_in = {0};
        Load_Out bad_out = {0};
        bad_in.parentHandle = g_parent_handle;
        memcpy(&bad_in.inPrivate, &g_create_out.outPrivate,
               sizeof(bad_in.inPrivate));
        memcpy(&bad_in.inPublic, &g_create_out.outPublic,
               sizeof(bad_in.inPublic));

        /* Corrupt byte 10 (well within the TPMT_SENSITIVE area) */
        if (bad_in.inPrivate.size > 10) {
            bad_in.inPrivate.buffer[10] ^= 0xFF;
        }

        res = TPM2_Load(&bad_in, &bad_out);
        assert(res != TPM_RC_SUCCESS,
               "Load integrity: corrupted private blob should fail\n",
               "!= TPM_RC_SUCCESS", string_from_TPM_RC(res));
        DBG_PRINTF("[TEST] Load integrity (corrupt blob): rc=0x%08lX (%s)\n",
                   (unsigned long)res, string_from_TPM_RC(res));
    }

    DBG_PRINT("[TEST] Load private blob integrity: DONE\n");
}
#endif

/* ===========================================================================
 * GROUP E: Sign Integration Tests  (verification §6)
 * ===========================================================================
 */
#if defined(TPM_TEST_ENABLE_SIGN_INTEGRATION) && \
    defined(TPM_TEST_ENABLE_SIGN) && defined(TPM_TEST_ENABLE_LOAD)
void TPM2_Sign_integration_tests(void) {
    TPM_RC res;

    DBG_PRINT("\n[TEST] Sign integration tests\n");

    if (!g_key_loaded) {
        DBG_PRINT("[TEST] Sign integration: SKIPPED (key not loaded)\n");
        return;
    }

    /* E1 + E2 + E3 — Sign with the loaded child key handle */
    {
        Sign_In in = {0};
        Sign_Out out = {0};

        in.keyHandle = g_load_out.objectHandle;
        in.inScheme.scheme = TPM_ALG_NULL;
        in.inScheme.hashAlg = TPM_ALG_NULL;

        /* Use a 32-byte SHA-256 digest */
        in.digest.size = 32;
        for (int i = 0; i < 32; i++) {
            in.digest.buffer[i] = (uint8_t)(0x41 + (i % 26));
        }

        res = TPM2_Sign(&in, &out);

        /* E1: keyHandle references loaded key → SUCCESS */
        assert(res == TPM_RC_SUCCESS,
               "Sign E1: Sign with loaded key should succeed\n",
               string_from_TPM_RC(TPM_RC_SUCCESS), string_from_TPM_RC(res));

        if (res == TPM_RC_SUCCESS) {
            /* E3: signature must be non-empty */
            assert(out.signature.signature.size > 0,
                   "Sign E3: signature is empty\n", "> 0", "0");

            /* E2: scheme fields populated */
            assert(out.signature.sigAlg != 0,
                   "Sign E2: sigAlg is zero\n", "!= 0", "0");

            DBG_PRINTF("[TEST] Sign E1-E3: sig_size=%u, sigAlg=0x%04X\n",
                       out.signature.signature.size, out.signature.sigAlg);
        }
    }

    /* E4 — Invalid hash algorithm → expect error */
    {
        Sign_In in = {0};
        Sign_Out out = {0};

        in.keyHandle = g_load_out.objectHandle;
        in.inScheme.scheme = TPM_ALG_NULL;
        in.inScheme.hashAlg = 0xFFFF; /* bogus */

        in.digest.size = 32;
        for (int i = 0; i < 32; i++) {
            in.digest.buffer[i] = (uint8_t)i;
        }

        res = TPM2_Sign(&in, &out);
        assert(res != TPM_RC_SUCCESS,
               "Sign E4: invalid hashAlg should fail\n",
               "!= TPM_RC_SUCCESS", string_from_TPM_RC(res));
        DBG_PRINTF("[TEST] Sign E4 (bad hashAlg): rc=0x%08lX (%s)\n",
                   (unsigned long)res, string_from_TPM_RC(res));
    }

    DBG_PRINT("[TEST] Sign integration tests: DONE\n");
}
#endif

/* ===========================================================================
 * GROUP F: Workflow Integration Tests  (verification §8)
 * ===========================================================================
 */
#if defined(TPM_TEST_ENABLE_WORKFLOW_INTEGRATION) && \
    defined(TPM_TEST_ENABLE_CREATEPRIMARY) &&        \
    defined(TPM_TEST_ENABLE_CREATE) &&                \
    defined(TPM_TEST_ENABLE_LOAD)
void TPM2_Workflow_integration_tests(void) {
    TPM_RC res;

    DBG_PRINT("\n[TEST] Workflow integration tests\n");

    if (!g_key_loaded) {
        DBG_PRINT("[TEST] Workflow: SKIPPED (key not loaded)\n");
        return;
    }

    /* F1 — End-to-end: CreatePrimary→Create→Load→Sign */
#ifdef TPM_TEST_ENABLE_SIGN
    {
        Sign_In in = {0};
        Sign_Out out = {0};

        in.keyHandle = g_load_out.objectHandle;
        in.inScheme.scheme = TPM_ALG_NULL;
        in.inScheme.hashAlg = TPM_ALG_NULL;
        in.digest.size = 32;
        for (int i = 0; i < 32; i++) {
            in.digest.buffer[i] = (uint8_t)(0xBB ^ (uint8_t)i);
        }

        res = TPM2_Sign(&in, &out);
        assert(res == TPM_RC_SUCCESS,
               "Workflow F1: end-to-end Sign should succeed\n",
               string_from_TPM_RC(TPM_RC_SUCCESS), string_from_TPM_RC(res));
        if (res == TPM_RC_SUCCESS) {
            assert(out.signature.signature.size > 0,
                   "Workflow F1: signature is empty\n", "> 0", "0");
        }
        DBG_PRINTF("[TEST] Workflow F1 (e2e sign): rc=0x%08lX\n",
                   (unsigned long)res);
    }
#endif

    /* F2 — Reuse protection: mutate outPrivate and try Load again */
    {
        Load_In bad_in = {0};
        Load_Out bad_out = {0};
        bad_in.parentHandle = g_parent_handle;
        memcpy(&bad_in.inPrivate, &g_create_out.outPrivate,
               sizeof(bad_in.inPrivate));
        memcpy(&bad_in.inPublic, &g_create_out.outPublic,
               sizeof(bad_in.inPublic));

        /* XOR a byte in the private blob */
        if (bad_in.inPrivate.size > 5) {
            bad_in.inPrivate.buffer[5] ^= 0xAA;
        }

        res = TPM2_Load(&bad_in, &bad_out);
        assert(res != TPM_RC_SUCCESS,
               "Workflow F2: modified outPrivate should fail Load\n",
               "!= TPM_RC_SUCCESS", string_from_TPM_RC(res));
        DBG_PRINTF("[TEST] Workflow F2 (reuse protection): rc=0x%08lX (%s)\n",
                   (unsigned long)res, string_from_TPM_RC(res));
    }

    /* F3 — Multiple objects under one primary: create + load second child */
    {
        Create_In in2 = {0};
        Create_Out out2 = {0};

        in2.parentHandle = g_parent_handle;
        in2.inSensitive.size = 0;
        in2.inSensitive.sensitive.userAuth.size = 0;
        in2.inSensitive.sensitive.data.size = 0;
        in2.inPublic.size = 0;
        in2.inPublic.publicArea.type = TPM_ALG_RSA;
        in2.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
        in2.inPublic.publicArea.objectAttributes.fixedTPM = 1;
        in2.inPublic.publicArea.objectAttributes.fixedParent = 1;
        in2.inPublic.publicArea.objectAttributes.sensitiveDataOrigin = 1;
        in2.inPublic.publicArea.objectAttributes.userWithAuth = 1;
        in2.inPublic.publicArea.objectAttributes.sign_encrypt = 1;
        in2.inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm =
            TPM_ALG_NULL;
        in2.inPublic.publicArea.parameters.rsaDetail.scheme.scheme =
            TPM_ALG_RSASSA;
        in2.inPublic.publicArea.parameters.rsaDetail.scheme.details.anySig
            .hashAlg = TPM_ALG_SHA256;
        in2.inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
        in2.inPublic.publicArea.parameters.rsaDetail.exponent = 0;
        in2.inPublic.publicArea.unique.rsa.size = 0;
        in2.outsideInfo.size = 0;
        in2.creationPCR.count = 0;

        res = TPM2_Create(&in2, &out2);
        assert(res == TPM_RC_SUCCESS,
               "Workflow F3: second Create should succeed\n",
               string_from_TPM_RC(TPM_RC_SUCCESS), string_from_TPM_RC(res));

        if (res == TPM_RC_SUCCESS) {
            Load_In load2 = {0};
            Load_Out load_out2 = {0};
            load2.parentHandle = g_parent_handle;
            memcpy(&load2.inPrivate, &out2.outPrivate,
                   sizeof(load2.inPrivate));
            memcpy(&load2.inPublic, &out2.outPublic,
                   sizeof(load2.inPublic));

            res = TPM2_Load(&load2, &load_out2);
            assert(res == TPM_RC_SUCCESS,
                   "Workflow F3: second Load should succeed\n",
                   string_from_TPM_RC(TPM_RC_SUCCESS),
                   string_from_TPM_RC(res));

            if (res == TPM_RC_SUCCESS) {
                /* Handles must be distinct */
                assert(load_out2.objectHandle != g_load_out.objectHandle,
                       "Workflow F3: second handle must differ from first\n",
                       "different", "same");

                /* Second handle in transient range */
                uint8_t ht = (uint8_t)(load_out2.objectHandle >> HR_SHIFT);
                char exp_s[8], act_s[8];
                snprintf(exp_s, sizeof(exp_s), "0x80");
                snprintf(act_s, sizeof(act_s), "0x%02X", ht);
                assert(ht == 0x80,
                       "Workflow F3: second handle not transient\n",
                       exp_s, act_s);

                DBG_PRINTF("[TEST] Workflow F3: child1=0x%08lX, "
                           "child2=0x%08lX\n",
                           (unsigned long)g_load_out.objectHandle,
                           (unsigned long)load_out2.objectHandle);
            }
        }
    }

    DBG_PRINT("[TEST] Workflow integration tests: DONE\n");
}
#endif

/* ===========================================================================
 * GROUP G: Error Handling Tests  (verification §9)
 * ===========================================================================
 */
#ifdef TPM_TEST_ENABLE_ERROR_HANDLING
void TPM2_Error_handling_tests(void) {
    DBG_PRINT("\n[TEST] Error handling tests\n");

    /* G1 — TPM_RC_HANDLE for invalid handles: Load with bad parent */
#ifdef TPM_TEST_ENABLE_LOAD
    {
        Load_In bad_in = {0};
        Load_Out bad_out = {0};
        bad_in.parentHandle = 0xFFFFFFFF; /* invalid */
        bad_in.inPrivate.size = 1;        /* non-zero so we pass size check */
        bad_in.inPrivate.buffer[0] = 0xAA;

        TPM_RC res = TPM2_Load(&bad_in, &bad_out);
        assert(res != TPM_RC_SUCCESS,
               "Error G1: Load with invalid parent should fail\n",
               "!= TPM_RC_SUCCESS", string_from_TPM_RC(res));
        DBG_PRINTF("[TEST] Error G1 (bad handle): rc=0x%08lX (%s)\n",
                   (unsigned long)res, string_from_TPM_RC(res));
    }
#endif

    /* G2 — TPM_RC_VALUE / TPM_RC_HASH for empty data:
     *       Hash with data.size = 0 → expect error */
#ifdef TPM_TEST_ENABLE_HASH
    {
        Hash_In in = {0};
        Hash_Out out = {0};
        in.hashAlg = TPM_ALG_SHA256;
        in.data.size = 0; /* empty → should be rejected */

        TPM_RC res = TPM2_Hash(&in, &out);
        assert(res != TPM_RC_SUCCESS,
               "Error G2: Hash with empty data should fail\n",
               "!= TPM_RC_SUCCESS", string_from_TPM_RC(res));
        DBG_PRINTF("[TEST] Error G2 (empty hash data): rc=0x%08lX (%s)\n",
                   (unsigned long)res, string_from_TPM_RC(res));
    }
#endif

    DBG_PRINT("[TEST] Error handling tests: DONE\n");
}
#endif

/* ===========================================================================
 * GROUP H: Data Size Tests  (verification §10)
 * ===========================================================================
 */
#if defined(TPM_TEST_ENABLE_DATA_SIZES) && \
    defined(TPM_TEST_ENABLE_CREATEPRIMARY)
void TPM2_Data_size_tests(void) {
    DBG_PRINT("\n[TEST] Data size and boundary tests\n");

    /* H1 — TPM2B size enforced: Hash with data.size = 0 (empty) */
#ifdef TPM_TEST_ENABLE_HASH
    {
        Hash_In in = {0};
        Hash_Out out = {0};
        in.hashAlg = TPM_ALG_SHA256;
        in.data.size = 0;

        TPM_RC res = TPM2_Hash(&in, &out);
        assert(res != TPM_RC_SUCCESS,
               "DataSize H1: Hash with size=0 should fail\n",
               "!= TPM_RC_SUCCESS", string_from_TPM_RC(res));
    }
#endif

    /* H2 — RSA public key size matches template (2048 bits → 256 bytes) */
    {
        uint16_t unique_size = g_create_primary_out.outPublic.publicArea
                                   .unique.rsa.size;
        char exp_s[8], act_s[8];
        snprintf(exp_s, sizeof(exp_s), "256");
        snprintf(act_s, sizeof(act_s), "%u", unique_size);
        assert(unique_size == 256,
               "DataSize H2: RSA modulus size != 256 bytes\n", exp_s, act_s);
    }

    DBG_PRINT("[TEST] Data size tests: DONE\n");
}
#endif

/**
 * @brief Run all key management tests in sequence
 *
 * Tests are run in order because they share state:
 * CreatePrimary -> Create -> Load -> ReadPublic -> ObjectChangeAuth
 */
void TPM2_KeyManagement_test_suite(void) {
    DBG_PRINT("\n");
    DBG_PRINT("==================================================\n");
    DBG_PRINT("[SUITE] Key Management Tests\n");
    DBG_PRINT("==================================================\n");

    /* Reset shared state */
    g_key_created = false;
    g_key_loaded = false;
#ifdef TPM_TEST_ENABLE_CREATEPRIMARY
    memset(&g_create_primary_out, 0, sizeof(g_create_primary_out));
#endif
#ifdef TPM_TEST_ENABLE_CREATE
    memset(&g_create_out, 0, sizeof(g_create_out));
#endif
#ifdef TPM_TEST_ENABLE_LOAD
    memset(&g_load_out, 0, sizeof(g_load_out));
#endif

    /* Run tests in sequence */
#ifdef TPM_TEST_ENABLE_CREATEPRIMARY
    TPM2_CreatePrimary_test();
    TPM2_CreatePrimary_with_sessions_test();
#else
    DBG_PRINT("[TEST] TPM2_CreatePrimary: SKIPPED (not enabled)\n");
#endif

    /* GROUP B — CreatePrimary template match (§3) */
#if defined(TPM_TEST_ENABLE_CREATEPRIMARY_TEMPLATE_MATCH) && \
    defined(TPM_TEST_ENABLE_CREATEPRIMARY)
    TPM2_CreatePrimary_template_match_test();
#endif

    /* GROUP H — Data size tests (§10) — needs CreatePrimary output */
#if defined(TPM_TEST_ENABLE_DATA_SIZES) && \
    defined(TPM_TEST_ENABLE_CREATEPRIMARY)
    TPM2_Data_size_tests();
#endif

#if defined(TPM_TEST_ENABLE_CREATE) && defined(TPM_TEST_ENABLE_CREATEPRIMARY)
    TPM2_Create_test();
#elif defined(TPM_TEST_ENABLE_CREATE)
    DBG_PRINT("[TEST] TPM2_Create: SKIPPED (CreatePrimary not enabled)\n");
#endif

    /* GROUP C — Create negative tests (§4) */
#if defined(TPM_TEST_ENABLE_CREATE_NEGATIVE) && \
    defined(TPM_TEST_ENABLE_CREATEPRIMARY)
    TPM2_Create_negative_tests();
#endif

#if defined(TPM_TEST_ENABLE_LOAD) && defined(TPM_TEST_ENABLE_CREATE)
    TPM2_Load_test();
    TPM2_Load_negative_tests();
#elif defined(TPM_TEST_ENABLE_LOAD)
    DBG_PRINT("[TEST] TPM2_Load: SKIPPED (Create not enabled)\n");
#endif

    /* GROUP D — Load private blob integrity (§5) */
#if defined(TPM_TEST_ENABLE_LOAD_PRIVATE_INTEGRITY) && \
    defined(TPM_TEST_ENABLE_CREATE) && defined(TPM_TEST_ENABLE_LOAD)
    TPM2_Load_private_integrity_test();
#endif

#if defined(TPM_TEST_ENABLE_READPUBLIC) && defined(TPM_TEST_ENABLE_LOAD)
    TPM2_ReadPublic_test();
#elif defined(TPM_TEST_ENABLE_READPUBLIC)
    DBG_PRINT("[TEST] TPM2_ReadPublic: SKIPPED (Load not enabled)\n");
#endif

    /* GROUP E — Sign integration tests (§6) */
#if defined(TPM_TEST_ENABLE_SIGN_INTEGRATION) && \
    defined(TPM_TEST_ENABLE_SIGN) && defined(TPM_TEST_ENABLE_LOAD)
    TPM2_Sign_integration_tests();
#endif

    /* GROUP F — Workflow integration tests (§8) */
#if defined(TPM_TEST_ENABLE_WORKFLOW_INTEGRATION) && \
    defined(TPM_TEST_ENABLE_CREATEPRIMARY) &&        \
    defined(TPM_TEST_ENABLE_CREATE) &&                \
    defined(TPM_TEST_ENABLE_LOAD)
    TPM2_Workflow_integration_tests();
#endif

#if defined(TPM_TEST_ENABLE_OBJECTCHANGEAUTH) && defined(TPM_TEST_ENABLE_LOAD)
    TPM2_ObjectChangeAuth_test();
#elif defined(TPM_TEST_ENABLE_OBJECTCHANGEAUTH)
    DBG_PRINT("[TEST] TPM2_ObjectChangeAuth: SKIPPED (Load not enabled)\n");
#endif

    DBG_PRINT("==================================================\n");
    DBG_PRINT("[SUITE] Key Management Tests Complete\n");
    DBG_PRINT("==================================================\n\n");
}

void tpm_test(void) {
    tpm_wait_access();
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE,
                            (uint8_t *)"[INFO] TPM access granted\n", 26,
                            portMAX_DELAY);

    /* GROUP A — Transport & framing negative tests (§1) */
#ifdef TPM_TEST_ENABLE_TRANSPORT_NEGATIVE
    TPM2_Transport_negative_tests();
#endif

#ifdef TPM_TEST_ENABLE_NV_DEFINE
    TPM2_NV_DefineSpace_test();
#else
    DBG_PRINT("[TEST] TPM2_NV_DefineSpace: SKIPPED (not enabled)\n");
#endif

#ifdef TPM_TEST_ENABLE_NV_WRITE_READ
    TPM2_NV_WriteRead_test();
#else
    DBG_PRINT("[TEST] TPM2_NV_WriteRead: SKIPPED (not enabled)\n");
#endif

#ifdef TPM_TEST_ENABLE_HASH
    TPM2_Hash_smoke_test();
#else
    DBG_PRINT("[TEST] TPM2_Hash: SKIPPED (not enabled)\n");
#endif

    /* GROUP G — Error handling tests (§9) */
#ifdef TPM_TEST_ENABLE_ERROR_HANDLING
    TPM2_Error_handling_tests();
#endif

#ifdef TPM_TEST_ENABLE_SIGN
    TPM2_Sign_smoke_test();
#else
    DBG_PRINT("[TEST] TPM2_Sign: SKIPPED (not enabled)\n");
#endif

#ifdef TPM_TEST_ENABLE_VERIFY_SIGNATURE
    TPM2_VerifySignature_smoke_test();
#else
    DBG_PRINT("[TEST] TPM2_VerifySignature: SKIPPED (not enabled)\n");
#endif

#ifdef TPM_TEST_ENABLE_ENCRYPT_DECRYPT2
    TPM2_EncryptDecrypt2_smoke_test();
#else
    DBG_PRINT("[TEST] TPM2_EncryptDecrypt2: SKIPPED (not enabled)\n");
#endif

#ifdef TPM_TEST_ENABLE_RSA_ENCRYPT_DECRYPT
    TPM2_RSA_EncryptDecrypt_smoke_test();
#else
    DBG_PRINT("[TEST] TPM2_RSA_EncryptDecrypt: SKIPPED (not enabled)\n");
#endif

    /* Key Management Tests */
    TPM2_KeyManagement_test_suite();
}

int main(void) {
    IntCtrl_Ip_Init(&IntCtrlConfig_0);
    IntCtrl_Ip_EnableIrq(LPUART3_IRQn);

    Lpuart_Uart_Ip_Init(LPUART_INSTANCE, &Lpuart_Uart_Ip_xHwConfigPB_3);
    Lpuart_Uart_Ip_SyncSend(LPUART_INSTANCE,
                            (uint8_t *)"[INFO] Starting TPM Test\n", 25,
                            portMAX_DELAY);

    tpm_test();

    assert_report();

    while (1)
        ;

    return 0;
}

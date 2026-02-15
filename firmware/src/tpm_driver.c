/**
 * @file tpm_driver.c
 * @brief TPM FIFO driver — I/O primitives, control, and command dispatch.
 *
 * All TPM command wrappers are generated via three X-macros:
 *   - @c TPM2_InOut(F):   input + output (e.g. Sign, Hash, Load)
 *   - @c TPM2_In(F):      input only (e.g. Startup, NV_Write)
 *   - @c TPM2_NoInOut(F): no input (e.g. GetTestResult)
 *
 * Each macro expands to a full function that:
 *   1. Builds and sends the command header + input struct
 *   2. Calls tpm_go()
 *   3. Receives the response header
 *   4. Reads the output struct (if any) or drains extra bytes
 *
 * @see tpm_driver.h for declarations and public API.
 */

#include "tpm_platform.h"
#include "tpm_driver.h"
#include "tpm2_spec_protocol.h"
#include "tpm_tests_config.h"

/* ===========================================================================
 * I/O Primitives
 * ===========================================================================
 */

/**
 * @brief Busy-wait until TPM_STS.EXPECT is set.
 * @return @c true if EXPECT is set, @c false otherwise.
 */
bool tpm_send_rdy(void) {
    return TPM_STS & TPM_STS_EXPECT;
}

/**
 * @brief Busy-wait until TPM_STS.DATA_AVAIL is set.
 * @return @c true if DATA_AVAIL is set, @c false otherwise.
 */
bool tpm_receive_rdy(void) {
    return TPM_STS & TPM_STS_DATA_AVAIL;
}

/**
 * @brief Send data into TPM
 *
 * @note This could be made more efficient by using burstSize instead of waiting
 *       on every byte.
 *
 * @see tpm_driver.h for parameter documentation.
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
 *
 * @note This could be made more efficient by using burstSize instead of waiting
 *       on every byte.
 *
 * @see tpm_driver.h for parameter documentation.
 */
void tpm_receive(void *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        while (!tpm_receive_rdy())
            ;
        ((uint8_t *)data)[i] = TPM_DATA_FIFO;
    }
}

/* ===========================================================================
 * Control
 * ===========================================================================
 */

/**
 * @brief Request TPM locality and busy wait until it's granted
 */
void tpm_wait_access(void) {
    TPM_ACCESS = TPM_ACCESS_REQUEST_USE;
    while (!(TPM_ACCESS & TPM_ACCESS_ACTIVE_LOCAL))
        ;
}

/**
 * @brief Notify TPM that a command is about to be sent in
 */
void tpm_command_ready(void) {
    TPM_STS |= TPM_STS_COMMAND_READY;
}

/**
 * @brief Start the execution of a command
 */
void tpm_go(void) {
    TPM_STS |= TPM_STS_GO;
}

/* ===========================================================================
 * Helpers
 * ===========================================================================
 */

/* documented in tpm_driver.h */
size_t tpm_min_size(size_t a, size_t b) {
    return (a < b) ? a : b;
}

/* documented in tpm_driver.h */
void tpm_drain_bytes(size_t size) {
    uint8_t sink[16];
    while (size > 0) {
        size_t chunk = tpm_min_size(size, sizeof(sink));
        tpm_receive(sink, chunk);
        size -= chunk;
    }
}

/* ===========================================================================
 * Raw command helpers - used by transport / framing / error negative tests.
 * ===========================================================================
 */

#if defined(TPM_TEST_ENABLE_TRANSPORT_NEGATIVE) || \
    defined(TPM_TEST_ENABLE_ERROR_HANDLING)
/**
 * @brief Send a raw TPM command and return the response header.
 *
 * Builds a well-formed command header (tag + computed size + code),
 * transmits the optional payload, triggers execution, and reads back
 * the response header.  Any remaining response bytes are drained.
 *
 * Used by transport-negative and error-handling test suites to craft
 * arbitrary command sequences.
 *
 * @param[in] tag           TPM_ST tag for the command header.
 * @param[in] commandCode   TPM_CC command code.
 * @param[in] payload       Pointer to payload bytes (may be @c NULL).
 * @param[in] payload_size  Payload length in bytes.
 * @return The received response header.
 */
tpm_rsp_header_t tpm_send_raw_command(uint16_t tag, uint32_t commandCode,
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
tpm_rsp_header_t tpm_send_raw_command_bad_size(uint16_t tag,
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
 * Auth-session helpers
 * ===========================================================================
 */

/**
 * @brief Send empty password authorization area using __packed struct.
 */
void tpm_send_auth_area(void) {
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
void skip_auth_response_area(void) {
    TPMS_AUTH_RESPONSE_AREA area;
    tpm_receive(&area, sizeof(area));
}

/* ===========================================================================
 * TPM2 command wrapper macros (X-macro pattern)
 *
 * TPM2_InOut(F)  — generates  TPM_RC TPM2_F(F_In *in, F_Out *out)
 * TPM2_In(F)     — generates  TPM_RC TPM2_F(F_In *in)
 * TPM2_NoInOut(F)— generates  TPM_RC TPM2_F(F_Out *out)
 * ===========================================================================
 */

/* min_size alias used inside macros */
#define min_size tpm_min_size

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

#define TPM2_NoInOut(F)                                                    \
    TPM_RC TPM2_##F(F##_Out *out) {                                        \
        tpm_rsp_header_t rsp;                                              \
                                                                           \
        tpm_cmd_header_t cmd = {.tag = TPM_ST_NO_SESSIONS,                 \
                                .commandSize = sizeof(cmd),                \
                                .commandCode = TPM_CC_##F};                \
                                                                           \
        tpm_command_ready();                                               \
        tpm_send(&cmd, sizeof(cmd));                                       \
        tpm_go();                                                          \
                                                                           \
        tpm_receive(&rsp, sizeof(rsp));                                    \
                                                                           \
        size_t remaining = 0;                                              \
        if (rsp.responseSize >= sizeof(rsp) && rsp.responseSize <= 4096) { \
            remaining = (size_t)rsp.responseSize - sizeof(rsp);            \
        }                                                                  \
                                                                           \
        if (out != NULL) {                                                 \
            memset(out, 0, sizeof(*out));                                  \
        }                                                                  \
                                                                           \
        if (rsp.responseCode != TPM_RC_SUCCESS) {                          \
            tpm_drain_bytes(remaining);                                    \
            return rsp.responseCode;                                       \
        }                                                                  \
                                                                           \
        if (out != NULL) {                                                 \
            size_t to_read = min_size(remaining, sizeof(*out));            \
            tpm_receive(out, to_read);                                     \
            tpm_drain_bytes(remaining - to_read);                          \
        } else {                                                           \
            tpm_drain_bytes(remaining);                                    \
        }                                                                  \
                                                                           \
        return rsp.responseCode;                                           \
    }

/* ---- Instantiate command wrappers -------------------------------------- */

TPM2_InOut(GetRandom)

    TPM2_In(Startup);
TPM2_In(Shutdown);
TPM2_In(SelfTest);
TPM2_InOut(GetCapability);
TPM2_NoInOut(GetTestResult);

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

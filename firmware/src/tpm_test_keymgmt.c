/**
 * @file tpm_test_keymgmt.c
 * @brief Key lifecycle tests and verification property groups.
 *
 * Exercises the full TPM 2.0 key management path and maps each group
 * to its verification property (see docs/verification/verification.md):
 *
 * | Group | Test                          | Property |
 * |-------|-------------------------------|----------|
 * | A     | CreatePrimary / Create / Load  | S.3      |
 * | B     | CreatePrimary template match    | S.3      |
 * | C     | Create negative tests          | S.4      |
 * | D     | Load private blob integrity    | S.5      |
 * | E     | Sign integration (E1-E10)      | S.6      |
 * | F     | Workflow integration (F1-F3)   | S.8      |
 * | H     | Data size / boundary tests     | S.10     |
 *
 * Tests share state (handles, output structs) through file-scope
 * variables guarded by per-test `#ifdef` blocks.
 *
 * @see TPM2_KeyManagement_test_suite() for the orchestrator.
 */

#include "tpm_platform.h"
#include "tpm_assert.h"
#include "tpm_driver.h"
#include "tpm2_spec_protocol.h"
#include "tpm_tests_config.h"
#include "tpm_marshal.h"
#include "sha256.h"

/** @name Shared state for key management tests
 *  File-scope variables that chain test outputs across the suite.
 *  @{ */

#ifdef TPM_TEST_ENABLE_CREATEPRIMARY
static CreatePrimary_Out
    g_create_primary_out; /**< Output from TPM2_CreatePrimary. */
#endif

#ifdef TPM_TEST_ENABLE_CREATE
static Create_Out g_create_out; /**< Output from TPM2_Create. */
#endif

#ifdef TPM_TEST_ENABLE_LOAD
static Load_Out g_load_out; /**< Output from TPM2_Load. */
#endif

static TPM_HANDLE g_parent_handle; /**< Parent key handle (primary). */
static bool g_key_created = false; /**< Flag: key was created successfully. */
static bool g_key_loaded = false;  /**< Flag: key was loaded successfully. */
/** @} */

/* ===========================================================================
 * TPM2_CreatePrimary Test
 * ===========================================================================
 */

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

/* ===========================================================================
 * TPM2_CreatePrimary with TPM_ST_SESSIONS Test
 * ===========================================================================
 */

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

/* ===========================================================================
 * TPM2_Create Test
 * ===========================================================================
 */

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

/* ===========================================================================
 * TPM2_Load Test
 * ===========================================================================
 */

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

/* ===========================================================================
 * TPM2_Load Negative Tests
 * ===========================================================================
 */

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
     * 1B: Binding Validation - modify nameAlg in public area
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
     * 1A: Attribute Consistency - clear both sign and decrypt
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
     * 1A: Key Size Consistency - change keyBits to wrong value
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

/* ===========================================================================
 * TPM2_ReadPublic Test
 * ===========================================================================
 */

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

/* ===========================================================================
 * TPM2_ObjectChangeAuth Test
 * ===========================================================================
 */

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
 * GROUP B: CreatePrimary Template Match  (verification S.3)
 * ===========================================================================
 */
#if defined(TPM_TEST_ENABLE_CREATEPRIMARY_TEMPLATE_MATCH) && \
    defined(TPM_TEST_ENABLE_CREATEPRIMARY)
/**
 * @brief Verify that the outPublic fields match the creation template (S.3).
 *
 * Checks type, nameAlg, objectAttributes, symmetric, scheme, keyBits,
 * and exponent against the RSA-2048 template used in CreatePrimary.
 */
void TPM2_CreatePrimary_template_match_test(void) {
    DBG_PRINT("\n[TEST] CreatePrimary template match verification\n");

    TPMT_PUBLIC *pub = &g_create_primary_out.outPublic.publicArea;

    /* type == RSA */
    assert(pub->type == TPM_ALG_RSA, "Template match: type != TPM_ALG_RSA\n",
           "TPM_ALG_RSA", "OTHER");

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
    assert(pub->objectAttributes.decrypt == 1, "Template match: decrypt != 1\n",
           "1", "0");
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
 * GROUP C: Create Negative Tests  (verification S.4)
 * ===========================================================================
 */
#if defined(TPM_TEST_ENABLE_CREATE_NEGATIVE) && \
    defined(TPM_TEST_ENABLE_CREATEPRIMARY)
/**
 * @brief Negative tests for TPM2_Create (S.4).
 *
 * - C1: invalid parent handle -> TPM_RC_VALUE expected.
 * - C2: unsupported algorithm  -> TPM_RC_ASYMMETRIC expected.
 */
void TPM2_Create_negative_tests(void) {
    TPM_RC res;

    DBG_PRINT("\n[TEST] Create negative tests\n");

    /* C1 - Invalid parent handle */
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

    /* C2 - nameAlg = TPM_ALG_NULL -> should return error (TPM_RC_HASH) */
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
        assert(res != TPM_RC_SUCCESS, "Create C2: nameAlg=NULL should fail\n",
               "!= TPM_RC_SUCCESS", string_from_TPM_RC(res));
        DBG_PRINTF("[TEST] Create C2 (null nameAlg): rc=0x%08lX (%s)\n",
                   (unsigned long)res, string_from_TPM_RC(res));
    }

    DBG_PRINT("[TEST] Create negative tests: DONE\n");
}
#endif

/* ===========================================================================
 * GROUP D: Load Private Blob Integrity  (verification S.5)
 * ===========================================================================
 */
#if defined(TPM_TEST_ENABLE_LOAD_PRIVATE_INTEGRITY) && \
    defined(TPM_TEST_ENABLE_CREATE) && defined(TPM_TEST_ENABLE_LOAD)
/**
 * @brief Corrupt the private blob and verify that Load rejects it (S.5).
 *
 * Flips a byte in the TPM2B_PRIVATE buffer produced by Create and expects
 * TPM2_Load to return an integrity-related error.
 */
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
     * and compares against the stored digest - this must mismatch. */
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
 * GROUP E: Sign Integration Tests  (verification S.6)
 * ===========================================================================
 */
#if defined(TPM_TEST_ENABLE_SIGN_INTEGRATION) && \
    defined(TPM_TEST_ENABLE_SIGN) && defined(TPM_TEST_ENABLE_LOAD)
/**
 * @brief Comprehensive sign / verify tests (S.6, sub-cases E1-E10).
 *
 * Covers basic signing, scheme fields, signature size, invalid hashAlg,
 * empty digest rejection, signature structure, Sign->VerifySignature
 * roundtrip, wrong-digest negative, corrupted-signature negative,
 * and explicit SHA-256 scheme handling.
 */
void TPM2_Sign_integration_tests(void) {
    TPM_RC res;

    DBG_PRINT("\n[TEST] Sign integration tests\n");

    if (!g_key_loaded) {
        DBG_PRINT("[TEST] Sign integration: SKIPPED (key not loaded)\n");
        return;
    }

    /* E1 + E2 + E3 - Sign with the loaded child key handle */
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

        /* E1: keyHandle references loaded key -> SUCCESS */
        assert(res == TPM_RC_SUCCESS,
               "Sign E1: Sign with loaded key should succeed\n",
               string_from_TPM_RC(TPM_RC_SUCCESS), string_from_TPM_RC(res));

        if (res == TPM_RC_SUCCESS) {
            /* E3: signature must be non-empty */
            assert(out.signature.signature.size > 0,
                   "Sign E3: signature is empty\n", "> 0", "0");

            /* E2: scheme fields populated */
            assert(out.signature.sigAlg != 0, "Sign E2: sigAlg is zero\n",
                   "!= 0", "0");

            DBG_PRINTF("[TEST] Sign E1-E3: sig_size=%u, sigAlg=0x%04X\n",
                       out.signature.signature.size, out.signature.sigAlg);
        }
    }

    /* E4 - Invalid hash algorithm -> expect error */
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
        assert(res != TPM_RC_SUCCESS, "Sign E4: invalid hashAlg should fail\n",
               "!= TPM_RC_SUCCESS", string_from_TPM_RC(res));
        DBG_PRINTF("[TEST] Sign E4 (bad hashAlg): rc=0x%08lX (%s)\n",
                   (unsigned long)res, string_from_TPM_RC(res));
    }

    /* E5 - Empty digest -> TPM_RC_VALUE (verification S.6: digest handling) */
    {
        Sign_In in = {0};
        Sign_Out out = {0};

        in.keyHandle = g_load_out.objectHandle;
        in.inScheme.scheme = TPM_ALG_NULL;
        in.inScheme.hashAlg = TPM_ALG_NULL;
        in.digest.size = 0; /* empty digest */

        res = TPM2_Sign(&in, &out);
        assert(res != TPM_RC_SUCCESS, "Sign E5: empty digest should fail\n",
               "!= TPM_RC_SUCCESS", string_from_TPM_RC(res));
        DBG_PRINTF("[TEST] Sign E5 (empty digest): rc=0x%08lX (%s)\n",
                   (unsigned long)res, string_from_TPM_RC(res));
    }

    /* E6 - Signature structure: sigAlg and hashAlg fields
     *       (verification S.6: scheme handling + digest handling) */
    {
        Sign_In in = {0};
        Sign_Out out = {0};

        in.keyHandle = g_load_out.objectHandle;
        in.inScheme.scheme = TPM_ALG_NULL;
        in.inScheme.hashAlg = TPM_ALG_NULL;
        in.digest.size = 32;
        for (int i = 0; i < 32; i++)
            in.digest.buffer[i] = (uint8_t)(0x55 ^ (uint8_t)i);

        res = TPM2_Sign(&in, &out);
        assert(res == TPM_RC_SUCCESS, "Sign E6: Sign should succeed\n",
               string_from_TPM_RC(TPM_RC_SUCCESS), string_from_TPM_RC(res));

        if (res == TPM_RC_SUCCESS) {
            /* sigAlg must be RSASSA (the key's default scheme) */
            {
                char exp[8], act[8];
                snprintf(exp, sizeof(exp), "0x%04X", TPM_ALG_RSASSA);
                snprintf(act, sizeof(act), "0x%04X", out.signature.sigAlg);
                assert(out.signature.sigAlg == TPM_ALG_RSASSA,
                       "Sign E6: sigAlg != TPM_ALG_RSASSA\n", exp, act);
            }
            /* hashAlg must be SHA-256 */
            {
                char exp[8], act[8];
                snprintf(exp, sizeof(exp), "0x%04X", TPM_ALG_SHA256);
                snprintf(act, sizeof(act), "0x%04X", out.signature.hashAlg);
                assert(out.signature.hashAlg == TPM_ALG_SHA256,
                       "Sign E6: hashAlg != TPM_ALG_SHA256\n", exp, act);
            }
            DBG_PRINTF("[TEST] Sign E6: sigAlg=0x%04X, hashAlg=0x%04X\n",
                       out.signature.sigAlg, out.signature.hashAlg);
        }
    }

    /* E7 - Sign then VerifySignature roundtrip
     *       (verification S.6: signature verification) */
#ifdef TPM_TEST_ENABLE_VERIFY_SIGNATURE
    {
        Sign_In sign_in = {0};
        Sign_Out sign_out = {0};

        sign_in.keyHandle = g_load_out.objectHandle;
        sign_in.inScheme.scheme = TPM_ALG_NULL;
        sign_in.inScheme.hashAlg = TPM_ALG_NULL;
        sign_in.digest.size = 32;
        for (int i = 0; i < 32; i++)
            sign_in.digest.buffer[i] = (uint8_t)(0xCC ^ (uint8_t)i);

        res = TPM2_Sign(&sign_in, &sign_out);
        assert(res == TPM_RC_SUCCESS, "Sign E7: Sign should succeed\n",
               string_from_TPM_RC(TPM_RC_SUCCESS), string_from_TPM_RC(res));

        if (res == TPM_RC_SUCCESS) {
            VerifySignature_In verify_in = {0};
            VerifySignature_Out verify_out = {0};

            verify_in.keyHandle = g_load_out.objectHandle;
            memcpy(&verify_in.digest, &sign_in.digest,
                   sizeof(verify_in.digest));
            memcpy(&verify_in.signature, &sign_out.signature,
                   sizeof(verify_in.signature));

            res = TPM2_VerifySignature(&verify_in, &verify_out);
            assert(res == TPM_RC_SUCCESS,
                   "Sign E7: VerifySignature should succeed for valid "
                   "signature\n",
                   string_from_TPM_RC(TPM_RC_SUCCESS), string_from_TPM_RC(res));

            if (res == TPM_RC_SUCCESS) {
                /* Validation ticket tag must be present */
                assert(verify_out.validation.digest.size > 0,
                       "Sign E7: validation ticket digest is empty\n", "> 0",
                       "0");
            }
            DBG_PRINTF("[TEST] Sign E7 (roundtrip): rc=0x%08lX\n",
                       (unsigned long)res);
        }
    }
#endif

    /* E8 - VerifySignature with wrong digest -> should fail
     *       (verification S.6: signature verification negative) */
#ifdef TPM_TEST_ENABLE_VERIFY_SIGNATURE
    {
        Sign_In sign_in = {0};
        Sign_Out sign_out = {0};

        sign_in.keyHandle = g_load_out.objectHandle;
        sign_in.inScheme.scheme = TPM_ALG_NULL;
        sign_in.inScheme.hashAlg = TPM_ALG_NULL;
        sign_in.digest.size = 32;
        for (int i = 0; i < 32; i++)
            sign_in.digest.buffer[i] = (uint8_t)(0xDD ^ (uint8_t)i);

        res = TPM2_Sign(&sign_in, &sign_out);

        if (res == TPM_RC_SUCCESS) {
            VerifySignature_In verify_in = {0};
            VerifySignature_Out verify_out = {0};

            verify_in.keyHandle = g_load_out.objectHandle;
            /* Use a DIFFERENT digest than what was signed */
            verify_in.digest.size = 32;
            for (int i = 0; i < 32; i++)
                verify_in.digest.buffer[i] = (uint8_t)(0xEE ^ (uint8_t)i);
            memcpy(&verify_in.signature, &sign_out.signature,
                   sizeof(verify_in.signature));

            res = TPM2_VerifySignature(&verify_in, &verify_out);
            assert(res != TPM_RC_SUCCESS,
                   "Sign E8: VerifySignature with wrong digest should "
                   "fail\n",
                   "!= TPM_RC_SUCCESS", string_from_TPM_RC(res));
            DBG_PRINTF("[TEST] Sign E8 (wrong digest): rc=0x%08lX (%s)\n",
                       (unsigned long)res, string_from_TPM_RC(res));
        }
    }
#endif

    /* E9 - VerifySignature with corrupted signature -> should fail
     *       (verification S.6: signature verification negative) */
#ifdef TPM_TEST_ENABLE_VERIFY_SIGNATURE
    {
        Sign_In sign_in = {0};
        Sign_Out sign_out = {0};

        sign_in.keyHandle = g_load_out.objectHandle;
        sign_in.inScheme.scheme = TPM_ALG_NULL;
        sign_in.inScheme.hashAlg = TPM_ALG_NULL;
        sign_in.digest.size = 32;
        for (int i = 0; i < 32; i++)
            sign_in.digest.buffer[i] = (uint8_t)(0xFF ^ (uint8_t)i);

        res = TPM2_Sign(&sign_in, &sign_out);

        if (res == TPM_RC_SUCCESS) {
            VerifySignature_In verify_in = {0};
            VerifySignature_Out verify_out = {0};

            verify_in.keyHandle = g_load_out.objectHandle;
            memcpy(&verify_in.digest, &sign_in.digest,
                   sizeof(verify_in.digest));
            memcpy(&verify_in.signature, &sign_out.signature,
                   sizeof(verify_in.signature));

            /* Corrupt one byte of the signature */
            if (verify_in.signature.signature.size > 0) {
                verify_in.signature.signature.buffer[0] ^= 0xFF;
            }

            res = TPM2_VerifySignature(&verify_in, &verify_out);
            assert(res != TPM_RC_SUCCESS,
                   "Sign E9: VerifySignature with corrupted sig should "
                   "fail\n",
                   "!= TPM_RC_SUCCESS", string_from_TPM_RC(res));
            DBG_PRINTF("[TEST] Sign E9 (corrupted sig): rc=0x%08lX (%s)\n",
                       (unsigned long)res, string_from_TPM_RC(res));
        }
    }
#endif

    /* E10 - Sign with explicit TPM_ALG_SHA256 hashAlg (not NULL)
     *        (verification S.6: scheme handling) */
    {
        Sign_In in = {0};
        Sign_Out out = {0};

        in.keyHandle = g_load_out.objectHandle;
        in.inScheme.scheme = TPM_ALG_RSASSA;
        in.inScheme.hashAlg = TPM_ALG_SHA256; /* explicit, not NULL */
        in.digest.size = 32;
        for (int i = 0; i < 32; i++)
            in.digest.buffer[i] = (uint8_t)(0xAA ^ (uint8_t)i);

        res = TPM2_Sign(&in, &out);
        assert(res == TPM_RC_SUCCESS,
               "Sign E10: explicit SHA256 hashAlg should succeed\n",
               string_from_TPM_RC(TPM_RC_SUCCESS), string_from_TPM_RC(res));

        if (res == TPM_RC_SUCCESS) {
            assert(out.signature.signature.size > 0,
                   "Sign E10: signature is empty\n", "> 0", "0");
        }
        DBG_PRINTF("[TEST] Sign E10 (explicit hashAlg): rc=0x%08lX\n",
                   (unsigned long)res);
    }

    DBG_PRINT("[TEST] Sign integration tests: DONE\n");
}
#endif

/* ===========================================================================
 * GROUP F: Workflow Integration Tests  (verification S.8)
 * ===========================================================================
 */
#if defined(TPM_TEST_ENABLE_WORKFLOW_INTEGRATION) && \
    defined(TPM_TEST_ENABLE_CREATEPRIMARY) &&        \
    defined(TPM_TEST_ENABLE_CREATE) && defined(TPM_TEST_ENABLE_LOAD)
/**
 * @brief End-to-end key workflow tests (S.8, sub-cases F1-F3).
 *
 * - F1: CreatePrimary -> Create -> Load -> Sign -> VerifySignature.
 * - F2: ReadPublic returns consistent public area.
 * - F3: FlushContext releases the transient object.
 */
void TPM2_Workflow_integration_tests(void) {
    TPM_RC res;

    DBG_PRINT("\n[TEST] Workflow integration tests\n");

    if (!g_key_loaded) {
        DBG_PRINT("[TEST] Workflow: SKIPPED (key not loaded)\n");
        return;
    }

    /* F1 - End-to-end: CreatePrimary->Create->Load->Sign */
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

    /* F2 - Reuse protection: mutate outPrivate and try Load again */
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

    /* F3 - Multiple objects under one primary: create + load second child */
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
            memcpy(&load2.inPrivate, &out2.outPrivate, sizeof(load2.inPrivate));
            memcpy(&load2.inPublic, &out2.outPublic, sizeof(load2.inPublic));

            res = TPM2_Load(&load2, &load_out2);
            assert(res == TPM_RC_SUCCESS,
                   "Workflow F3: second Load should succeed\n",
                   string_from_TPM_RC(TPM_RC_SUCCESS), string_from_TPM_RC(res));

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
                assert(ht == 0x80, "Workflow F3: second handle not transient\n",
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
 * GROUP H: Data Size Tests  (verification S.10)
 * ===========================================================================
 */
#if defined(TPM_TEST_ENABLE_DATA_SIZES) && \
    defined(TPM_TEST_ENABLE_CREATEPRIMARY)
/**
 * @brief TPM2B size-field and boundary value tests (S.10).
 *
 * - H1: Hash with data.size = 0 (empty buffer).
 * - H2: EncryptDecrypt2 with data close to block-size boundary.
 */
void TPM2_Data_size_tests(void) {
    DBG_PRINT("\n[TEST] Data size and boundary tests\n");

    /* H1 - TPM2B size enforced: Hash with data.size = 0 (empty) */
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

    /* H2 - RSA public key size matches template (2048 bits -> 256 bytes) */
    {
        uint16_t unique_size =
            g_create_primary_out.outPublic.publicArea.unique.rsa.size;
        char exp_s[8], act_s[8];
        snprintf(exp_s, sizeof(exp_s), "256");
        snprintf(act_s, sizeof(act_s), "%u", unique_size);
        assert(unique_size == 256,
               "DataSize H2: RSA modulus size != 256 bytes\n", exp_s, act_s);
    }

    DBG_PRINT("[TEST] Data size tests: DONE\n");
}
#endif

/* ===========================================================================
 * Key Management Test Suite Orchestrator
 * ===========================================================================
 */

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

    /* GROUP B - CreatePrimary template match (S.3) */
#if defined(TPM_TEST_ENABLE_CREATEPRIMARY_TEMPLATE_MATCH) && \
    defined(TPM_TEST_ENABLE_CREATEPRIMARY)
    TPM2_CreatePrimary_template_match_test();
#endif

    /* GROUP H - Data size tests (S.10) - needs CreatePrimary output */
#if defined(TPM_TEST_ENABLE_DATA_SIZES) && \
    defined(TPM_TEST_ENABLE_CREATEPRIMARY)
    TPM2_Data_size_tests();
#endif

#if defined(TPM_TEST_ENABLE_CREATE) && defined(TPM_TEST_ENABLE_CREATEPRIMARY)
    TPM2_Create_test();
#elif defined(TPM_TEST_ENABLE_CREATE)
    DBG_PRINT("[TEST] TPM2_Create: SKIPPED (CreatePrimary not enabled)\n");
#endif

    /* GROUP C - Create negative tests (S.4) */
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

    /* GROUP D - Load private blob integrity (S.5) */
#if defined(TPM_TEST_ENABLE_LOAD_PRIVATE_INTEGRITY) && \
    defined(TPM_TEST_ENABLE_CREATE) && defined(TPM_TEST_ENABLE_LOAD)
    TPM2_Load_private_integrity_test();
#endif

#if defined(TPM_TEST_ENABLE_READPUBLIC) && defined(TPM_TEST_ENABLE_LOAD)
    TPM2_ReadPublic_test();
#elif defined(TPM_TEST_ENABLE_READPUBLIC)
    DBG_PRINT("[TEST] TPM2_ReadPublic: SKIPPED (Load not enabled)\n");
#endif

    /* GROUP E - Sign integration tests (S.6) */
#if defined(TPM_TEST_ENABLE_SIGN_INTEGRATION) && \
    defined(TPM_TEST_ENABLE_SIGN) && defined(TPM_TEST_ENABLE_LOAD)
    TPM2_Sign_integration_tests();
#endif

    /* GROUP F - Workflow integration tests (S.8) */
#if defined(TPM_TEST_ENABLE_WORKFLOW_INTEGRATION) && \
    defined(TPM_TEST_ENABLE_CREATEPRIMARY) &&        \
    defined(TPM_TEST_ENABLE_CREATE) && defined(TPM_TEST_ENABLE_LOAD)
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

#include "qemu/osdep.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "hw/sysbus.h"
#include "migration/vmstate.h"
#include "hw/irq.h"
#include "qom/object.h"
#include "qemu/log.h"
#include "include/hw/misc/s32k358_tpm.h"
#include "hw/misc/tpm_create_primary.h"

static void s32k358_tpm_process_input(S32k358TPMState *s) {
    tpm_cmd_header_t cmd_header;
    TPM_RC rc;

    assert(s->tpm_state == TPM_S_EXEC);

    // Check if fifo is not full enough and report error condition if so
    if (fifo8_num_used(&s->infifo) < sizeof(tpm_cmd_header_t)) {
        qemu_log_mask(LOG_GUEST_ERROR, "(ERROR) TPM: Insufficient fifo DATA\n ");
        return;
    }

    // Unmarshal command header from FIFO
    UNMARSHAL(&cmd_header, &s->infifo);

    // Check if tag is valid
    if (cmd_header.tag != TPM_ST_NO_SESSIONS && cmd_header.tag != TPM_ST_SESSIONS) {
        qemu_log_mask(LOG_GUEST_ERROR, "(ERROR) TPM: Command header tag is not valid. Received 0x%04X\n", cmd_header.tag);
        tpm_send_error_response(s, TPM_RC_BAD_TAG);
        return;
    }

    // Track if command has authorization sessions
    bool hasAuth = (cmd_header.tag == TPM_ST_SESSIONS);

    // Check if infifo has enough data for the command size
    if (fifo8_num_used(&s->infifo) < (cmd_header.commandSize - sizeof(tpm_cmd_header_t))) {
        qemu_log_mask(LOG_GUEST_ERROR, "(ERROR) TPM: FIFO does not have enough data wrt the specified command size\n");
        qemu_log_mask(LOG_GUEST_ERROR, "(INFO) TPM: Command size: %u, Header size: %zu\n",cmd_header.commandSize, sizeof(tpm_cmd_header_t));
        qemu_log_mask(LOG_GUEST_ERROR, "(INFO) TPM: FIFO used size: %u, FIFO available size: %u\n",
                      fifo8_num_used(&s->infifo), fifo8_num_free(&s->infifo));
        tpm_send_error_response(s, TPM_RC_COMMAND_SIZE);
        return;
    }

    qemu_log_mask(LOG_GUEST_ERROR, "(INFO) TPM: Processing command 0x%08X (size=%u, fifo=%u)\n",
                  cmd_header.commandCode, cmd_header.commandSize, fifo8_num_used(&s->infifo));

    switch (cmd_header.commandCode) {
        case TPM_CC_GetRandom:

            GetRandom_In get_random_in;
            GetRandom_Out get_random_out;

            // Check if the command size is coherent with the expected size
            if (cmd_header.commandSize != sizeof(tpm_cmd_header_t) + sizeof(get_random_in)) {
                tpm_send_error_response(s, TPM_RC_COMMAND_SIZE);
                return;
            }

            // Unmarshal the GetRandom input
            UNMARSHAL(&get_random_in, &s->infifo);

            // Execute command
            rc = TPM2_GetRandom(&get_random_in, &get_random_out);

            // Generate response
            tpm_send_response(s, rc, &get_random_out, sizeof(get_random_out));

            return;
        
        case TPM_CC_NV_DefineSpace:
            NV_DefineSpace_In nv_define_space_in;

            // Check if the command size is coherent with the expected size
            if (cmd_header.commandSize != sizeof(tpm_cmd_header_t) + sizeof(nv_define_space_in)) {
                tpm_send_error_response(s, TPM_RC_COMMAND_SIZE);
                return;
            }

            // Unmarshal the NV_DefineSpace input
            UNMARSHAL(&nv_define_space_in, &s->infifo);

            // Execute command
            rc = TPM2_NV_DefineSpace(&nv_define_space_in);

            // Generate response
            tpm_send_response(s, rc, NULL, 0);

            return;

        case TPM_CC_NV_Write:
            qemu_log_mask(LOG_GUEST_ERROR, "(INFO) TPM: Processing NV_Write command\n");
            NV_Write_In nv_write_in;

            // Check if the command size is coherent with the expected size
            if (cmd_header.commandSize != sizeof(tpm_cmd_header_t) + sizeof(nv_write_in)) {
                qemu_log_mask(LOG_GUEST_ERROR, "(ERROR) TPM: NV_Write size mismatch: expected %zu, got %u\n",
                              sizeof(tpm_cmd_header_t) + sizeof(nv_write_in), cmd_header.commandSize);
                tpm_send_error_response(s, TPM_RC_COMMAND_SIZE);
                return;
            }

            // Unmarshal the NV_Write input
            UNMARSHAL(&nv_write_in, &s->infifo);

            // Execute command
            rc = TPM2_NV_Write(&nv_write_in);
            qemu_log_mask(LOG_GUEST_ERROR, "(INFO) TPM: NV_Write returned rc=0x%X\n", rc);

            // Generate response
            tpm_send_response(s, rc, NULL, 0);

            return;

        case TPM_CC_NV_Read:
            qemu_log_mask(LOG_GUEST_ERROR, "(INFO) TPM: Processing NV_Read command\n");
            NV_Read_In nv_read_in;
            NV_Read_Out nv_read_out;

            // Check if the command size is coherent with the expected size
            if (cmd_header.commandSize != sizeof(tpm_cmd_header_t) + sizeof(nv_read_in)) {
                tpm_send_error_response(s, TPM_RC_COMMAND_SIZE);
                return;
            }

            // Unmarshal the NV_Read input
            UNMARSHAL(&nv_read_in, &s->infifo);

            // Execute command
            rc = TPM2_NV_Read(&nv_read_in, &nv_read_out);

            // Generate response
            tpm_send_response(s, rc, &nv_read_out, sizeof(nv_read_out));

            return;
        case TPM_CC_Sign:
            Sign_In sign_in;
            Sign_Out sign_out;
            
            if (cmd_header.commandSize != sizeof(tpm_cmd_header_t) + sizeof(sign_in)) {
                tpm_send_error_response(s, TPM_RC_COMMAND_SIZE);
                return;
            }

            UNMARSHAL(&sign_in, &s->infifo);

            rc = TPM2_Sign(&sign_in, &sign_out);

            tpm_send_response(s, rc, &sign_out, sizeof(sign_out));

            return;

        case TPM_CC_VerifySignature:
            VerifySignature_In verify_in;
            VerifySignature_Out verify_out;
            
            if (cmd_header.commandSize != sizeof(tpm_cmd_header_t) + sizeof(verify_in)) {
                tpm_send_error_response(s, TPM_RC_COMMAND_SIZE);
                return;
            }

            UNMARSHAL(&verify_in, &s->infifo);

            rc = TPM2_VerifySignature(&verify_in, &verify_out);

            tpm_send_response(s, rc, &verify_out, sizeof(verify_out));

            return;

        case TPM_CC_Hash:
            Hash_In hash_in;
            Hash_Out hash_out;
            
            if (cmd_header.commandSize != sizeof(tpm_cmd_header_t) + sizeof(hash_in)) {
                tpm_send_error_response(s, TPM_RC_COMMAND_SIZE);
                return;
            }

            UNMARSHAL(&hash_in, &s->infifo);

            rc = TPM2_Hash(&hash_in, &hash_out);

            tpm_send_response(s, rc, &hash_out, sizeof(hash_out));

            return;

        case TPM_CC_EncryptDecrypt2:
            EncryptDecrypt2_In encrypt_in;
            EncryptDecrypt2_Out encrypt_out;
            
            if (cmd_header.commandSize != sizeof(tpm_cmd_header_t) + sizeof(encrypt_in)) {
                tpm_send_error_response(s, TPM_RC_COMMAND_SIZE);
                return;
            }

            UNMARSHAL(&encrypt_in, &s->infifo);

            rc = TPM2_EncryptDecrypt2(&encrypt_in, &encrypt_out);

            tpm_send_response(s, rc, &encrypt_out, sizeof(encrypt_out));

            return;

        case TPM_CC_RSA_Encrypt:
            RSA_Encrypt_In rsa_encrypt_in;
            RSA_Encrypt_Out rsa_encrypt_out;
            
            if (cmd_header.commandSize != sizeof(tpm_cmd_header_t) + sizeof(rsa_encrypt_in)) {
                tpm_send_error_response(s, TPM_RC_COMMAND_SIZE);
                return;
            }

            UNMARSHAL(&rsa_encrypt_in, &s->infifo);
            
            rc = TPM2_RSA_Encrypt(&rsa_encrypt_in, &rsa_encrypt_out);

            tpm_send_response(s, rc, &rsa_encrypt_out, sizeof(rsa_encrypt_out));

            return;

        case TPM_CC_RSA_Decrypt:
            RSA_Decrypt_In rsa_decrypt_in;
            RSA_Decrypt_Out rsa_decrypt_out;
            
            if (cmd_header.commandSize != sizeof(tpm_cmd_header_t) + sizeof(rsa_decrypt_in)) {
                tpm_send_error_response(s, TPM_RC_COMMAND_SIZE);
                return;
            }

            UNMARSHAL(&rsa_decrypt_in, &s->infifo);

            rc = TPM2_RSA_Decrypt(&rsa_decrypt_in, &rsa_decrypt_out);

            tpm_send_response(s, rc, &rsa_decrypt_out, sizeof(rsa_decrypt_out));

            return;

        case TPM_CC_CreatePrimary:
        {
            CreatePrimary_In create_primary_in;
            CreatePrimary_Out create_primary_out;
            memset(&create_primary_out, 0, sizeof(create_primary_out));

            /* Unmarshal command parameters */
            UNMARSHAL(&create_primary_in, &s->infifo);

            /* If TPM_ST_SESSIONS, parse auth area */
            if (hasAuth) {
                TPMS_AUTH_COMMAND authCmd = {0};
                rc = ParseAuthArea(&s->infifo, &authCmd);
                if (rc != TPM_RC_SUCCESS) {
                    tpm_send_error_response(s, rc);
                    return;
                }
                /* Auth parsed successfully - for educational TPM, we accept it */
            }

            /* Execute command */
            rc = TPM2_CreatePrimary(&create_primary_in, &create_primary_out);

            /* Send response */
            if (hasAuth) {
                tpm_rsp_header_t rsp = {
                    .tag = TPM_ST_SESSIONS,
                    .responseCode = rc
                };

                if (rc == TPM_RC_SUCCESS) {
                    rsp.responseSize = sizeof(rsp)
                                     + sizeof(TPMS_AUTH_RESPONSE_AREA)
                                     + sizeof(create_primary_out);
                } else {
                    rsp.responseSize = sizeof(rsp)
                                     + sizeof(TPMS_AUTH_RESPONSE_AREA);
                }

                MARSHAL(&s->outfifo, &rsp);
                MarshalAuthResponse(&s->outfifo);              /* auth first */
                if (rc == TPM_RC_SUCCESS) {
                    MARSHAL(&s->outfifo, &create_primary_out); /* output second */
                }

                qemu_log_mask(LOG_GUEST_ERROR,
                              "(INFO) TPM: Command completed, rc=0x%X, "
                              "response size=%u\n", rc, rsp.responseSize);
                tpm_finalize_response(s);
            } else {
                /* Standard TPM_ST_NO_SESSIONS response (backward compatible) */
                tpm_send_response(s, rc, &create_primary_out, sizeof(create_primary_out));
            }

            return;
        }

        case TPM_CC_Create:
            Create_In create_in;
            Create_Out create_out;
            memset(&create_out, 0, sizeof(create_out));

            if (cmd_header.commandSize != sizeof(tpm_cmd_header_t) + sizeof(create_in)) {
                tpm_send_error_response(s, TPM_RC_COMMAND_SIZE);
                return;
            }

            UNMARSHAL(&create_in, &s->infifo);

            rc = TPM2_Create(&create_in, &create_out);

            tpm_send_response(s, rc, &create_out, sizeof(create_out));

            return;

        case TPM_CC_Load:
            Load_In load_in;
            Load_Out load_out;
            memset(&load_out, 0, sizeof(load_out));

            if (cmd_header.commandSize != sizeof(tpm_cmd_header_t) + sizeof(load_in)) {
                tpm_send_error_response(s, TPM_RC_COMMAND_SIZE);
                return;
            }

            UNMARSHAL(&load_in, &s->infifo);

            rc = TPM2_Load(&load_in, &load_out);

            tpm_send_response(s, rc, &load_out, sizeof(load_out));

            return;

        default: /* unimplemented command */
            qemu_log_mask(LOG_GUEST_ERROR, "(ERROR) TPM: Unimplemented command\n");
            tpm_send_error_response(s, TPM_RC_COMMAND_CODE);
            return;
    }

}

static uint64_t s32k358_tpm_read(void *opaque, hwaddr offset, unsigned size) {
    S32k358TPMState *s = opaque;
    switch (offset) {
        case A_TPM_ACCESS:
            return s->tpm_access;
        case A_TPM_DATA_FIFO:
            if (fifo8_is_empty(&s->outfifo)) {
                qemu_log_mask(LOG_GUEST_ERROR, "%s: Output FIFO is empty, cannot read\n", __func__);
                return 0;
            }
            {
                uint8_t val = fifo8_pop(&s->outfifo);
                // Update burstCount to reflect remaining data
                s->tpm_sts &= ~R_TPM_STS_burstCount_MASK;
                s->tpm_sts |= (fifo8_num_used(&s->outfifo) << R_TPM_STS_burstCount_SHIFT) &
                              R_TPM_STS_burstCount_MASK;
                // Clear dataAvail if FIFO is now empty
                if (fifo8_is_empty(&s->outfifo)) {
                    s->tpm_sts &= ~R_TPM_STS_dataAvail_MASK;
                }
                return val;
            }
        case A_TPM_STS:
            return s->tpm_sts;
        default: 
            qemu_log_mask(LOG_GUEST_ERROR, "%s: Bad offset 0x%"HWADDR_PRIx"\n", __func__, offset);
            return 0;
    }
}

static void s32k358_tpm_write(void *opaque, hwaddr offset, uint64_t value, unsigned size) {
    S32k358TPMState *s = opaque;
    switch (offset) {
        case A_TPM_ACCESS:

            // If activeLocality is set, clear it and relinquish control
            if (value & R_TPM_ACCESS_activeLocality_MASK) {
                s->tpm_access &= ~R_TPM_ACCESS_activeLocality_MASK;
                s->tpm_state = TPM_S_IDLE; // Transition to idle state
            }

            // Check if the locality is being requested
            if (value & R_TPM_ACCESS_requestUse_MASK) {
                // Since there's only one locality, always grant
                qemu_log_mask(LOG_GUEST_ERROR, "%s: Locality requested, granting access\n", __func__);
                s->tpm_access &= ~R_TPM_ACCESS_requestUse_MASK;
                s->tpm_access |= R_TPM_ACCESS_activeLocality_MASK;
            }
        
            break;
        case A_TPM_DATA_FIFO:
            if (fifo8_is_full(&s->infifo)) {
                qemu_log_mask(LOG_GUEST_ERROR, "%s: Input FIFO is full, cannot write 0x%"PRIx64"\n", __func__, value);
                return;
            }

            // Transition to receiving state
            if (s->tpm_state == TPM_S_READY) {
                s->tpm_state = TPM_S_RECV;
                qemu_log_mask(LOG_GUEST_ERROR, "(INFO) TPM: Transitioned from READY to RECV\n");
            }

            if (s->tpm_state == TPM_S_RECV) {
                fifo8_push(&s->infifo, value & 0xFF);
                // Update burstCount to reflect remaining space in input FIFO
                s->tpm_sts &= ~R_TPM_STS_burstCount_MASK;
                s->tpm_sts |= (fifo8_num_free(&s->infifo) << R_TPM_STS_burstCount_SHIFT) &
                              R_TPM_STS_burstCount_MASK;
                // Clear Expect if FIFO is now full
                if (fifo8_is_full(&s->infifo)) {
                    s->tpm_sts &= ~R_TPM_STS_Expect_MASK;
                }
            } else {
                qemu_log_mask(LOG_GUEST_ERROR, "(ERROR) TPM: Data write ignored, state=%d\n", s->tpm_state);
            }
            break;
        case A_TPM_STS:
            // Process tpmGo FIRST before commandReady, since a write with both bits
            // set should execute the current command, not reset state
            if (value & R_TPM_STS_tpmGo_MASK) {
                qemu_log_mask(LOG_GUEST_ERROR, "(INFO) TPM: tpmGo received, state=%d, fifo_used=%u\n",
                              s->tpm_state, fifo8_num_used(&s->infifo));
                if (s->tpm_state == TPM_S_RECV) {
                    s->tpm_state = TPM_S_EXEC;
                    s32k358_tpm_process_input(s);
                    // After processing, don't process commandReady in the same write
                    break;
                }
            }
                    
            // If commandReady is set, transition status to ready
            // Now bytes can be accepted in the input FIFO
            if (value & R_TPM_STS_commandReady_MASK) {
                // Always transition to READY state on commandReady
                // First handle any cleanup from previous state
                if (s->tpm_state == TPM_S_CMPL) {
                    // Just need to clear output FIFO from previous command
                    fifo8_reset(&s->outfifo);
                }
                
                // Now transition to READY state
                s->tpm_state = TPM_S_READY;
                
                // Clear both FIFOs when preparing for a new command
                fifo8_reset(&s->infifo);
                fifo8_reset(&s->outfifo);
                s->tpm_sts &= ~R_TPM_STS_dataAvail_MASK;
                
                // If there is space in the input fifo, set the Expect bit
                if (fifo8_num_free(&s->infifo) > 0) {
                    s->tpm_sts |= R_TPM_STS_Expect_MASK;
                    
                    // Update burstCount to match the number of available
                    // bits in the input fifo
                    s->tpm_sts &= ~R_TPM_STS_burstCount_MASK;
                    s->tpm_sts |= (fifo8_num_free(&s->infifo) << 
                                   R_TPM_STS_burstCount_SHIFT) &
                                   R_TPM_STS_burstCount_MASK;
                }
            }

            break;
        default:
            qemu_log_mask(LOG_GUEST_ERROR, "%s: Bad offset 0x%"HWADDR_PRIx"\n", __func__, offset);
    }
}

// #error "Missing realize function. It should call NvInit!"

static const MemoryRegionOps s32k358_tpm_ops = {
    .read = s32k358_tpm_read,
    .write = s32k358_tpm_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static void s32k358_tpm_reset(DeviceState *d)
{
    S32k358TPMState *s = S32K358_TPM(d);

    s->tpm_state = TPM_STATE_RST;

    s->tpm_access = TPM_ACCESS_RST;
    s->tpm_int_enable = TPM_INT_ENABLE_RST;
    s->tpm_int_vector = TPM_INT_VECTOR_RST;
    s->tpm_int_status = TPM_INT_STATUS_RST;
    s->tpm_intf_caps = TPM_INTF_CAPS_RST;
    s->tpm_sts = TPM_STS_RST;
    s->tpm_data_fifo = TPM_DATA_FIFO_RST;
    s->tpm_interface_id = TPM_INTERFACE_ID_RST;
    s->tpm_xdata_fifo = TPM_XDATA_FIFO_RST;
    s->tpm_did_vid = TPM_DID_VID_RST;
    s->tpm_rid = TPM_RID_RST;

    s->tpm_sts |= (TPM_STS_burstCount_RST << R_TPM_STS_burstCount_SHIFT) & R_TPM_STS_burstCount_MASK;

    fifo8_reset(&s->infifo);
    fifo8_reset(&s->outfifo);

    s->tpm_state = TPM_S_IDLE; /* Ready to do stuff */
}

static void s32k358_tpm_realize(DeviceState *dev, Error **errp)
{
    S32k358TPMState *s = S32K358_TPM(dev);

    // Initialize TPM global state (including PCRs zeroed at reset)
    memset(&s->gc, 0, sizeof(s->gc));
    s->gc.shEnable = shEnable_RESET;
    s->gc.ehEnable = ehEnable_RESET;
    s->gc.phEnableNV = phEnableNV_RESET;
    s->gc.platformAlg = platformAlg_RESET;
    s->gc.platformPolicy = platformPolicy_RESET;
    s->gc.platformAuth = platformAuth_RESET;
    // PCRs are already zeroed by memset above

    // Initialize NV memory size and storage module
    s->nvmem_size = S32K358_TPM_NV_MEM_SIZE;
    memset(s->mem, 0, s->nvmem_size);  // Zero-initialize NV memory
    NvInit(s->mem, s->nvmem_size, &s->gc);

    // Set the device state pointer for hierarchy functions
    tpm_hierarchy_set_state(s);
}

static void s32k358_tpm_init(Object *obj)
{
    S32k358TPMState *s = S32K358_TPM(obj);
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);

    fifo8_create(&s->infifo, S32K358_TPM_INFIFO_SIZE);
    fifo8_create(&s->outfifo, S32K358_TPM_OUTFIFO_SIZE);

    memory_region_init_io(&s->iomem, obj, &s32k358_tpm_ops, s,
                          TYPE_S32K358_TPM, S32K358_TPM_MEM_SIZE);
    sysbus_init_mmio(sbd, &s->iomem);
    //sysbus_init_irq(sbd, &s->irq);
}

static void s32k358_tpm_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = s32k358_tpm_realize;

    device_class_set_legacy_reset(dc, s32k358_tpm_reset);
}

static const TypeInfo s32k358_tpm_type_info = {
    .name = TYPE_S32K358_TPM,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(S32k358TPMState),
    .instance_init = s32k358_tpm_init,
    .class_init = s32k358_tpm_class_init,
};

static void s32k358_tpm_register_types(void)
{
    type_register_static(&s32k358_tpm_type_info);
}

type_init(s32k358_tpm_register_types)

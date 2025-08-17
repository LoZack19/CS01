#include "qemu/osdep.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "hw/sysbus.h"
#include "migration/vmstate.h"
#include "hw/irq.h"
#include "qom/object.h"
#include "qemu/log.h"
#include "include/hw/misc/s32k358_tpm.h"

static void s32k358_tpm_process_input(S32k358TPMState *s) {
    tpm_cmd_header_t cmd_header;

    assert(s->tpm_state == TPM_S_EXEC);

    // Check if fifo is not full enough and report error condition if so
    if (fifo8_num_used(&s->infifo) < sizeof(tpm_cmd_header_t)) {
        qemu_log_mask(LOG_GUEST_ERROR, "(ERROR) TPM: Insufficient fifo DATA\n ");
        return;
    }

    // Unmarshal command header from FIFO
    tpm_cmd_header_unmarshal(&s->infifo, &cmd_header);

    // Check if tag is valid
    if (cmd_header.tag != TPM_ST_NO_SESSIONS && cmd_header.tag != TPM_ST_SESSIONS) {
        qemu_log_mask(LOG_GUEST_ERROR, "(ERROR) TPM: Command header tag is not valid. Received 0x%04X\n", cmd_header.tag);
        tpm_error_response(s, TPM_RC_BAD_TAG);
        return;
    }

    // Check if infifo has enough data for the command size
    if (fifo8_num_used(&s->infifo) < (cmd_header.commandSize - sizeof(tpm_cmd_header_t))) {
        qemu_log_mask(LOG_GUEST_ERROR, "(ERROR) TPM: FIFO does not have enough data wrt the specified command size\n");
        qemu_log_mask(LOG_GUEST_ERROR, "(INFO) TPM: Command size: %u, Header size: %zu\n",cmd_header.commandSize, sizeof(tpm_cmd_header_t));
        qemu_log_mask(LOG_GUEST_ERROR, "(INFO) TPM: FIFO used size: %u, FIFO available size: %u\n",
                      fifo8_num_used(&s->infifo), fifo8_num_free(&s->infifo));
        tpm_error_response(s, TPM_RC_COMMAND_SIZE);
        return;
    }

    switch (cmd_header.commandCode) {
        case TPM_CC_GetRandom:

            GetRandom_In get_random_in;
            GetRandom_Out get_random_out;
            
            // Check if the command size is coherent with the expected size
            if (cmd_header.commandSize != sizeof(tpm_cmd_header_t) + sizeof(get_random_in)) {
                tpm_error_response(s, TPM_RC_COMMAND_SIZE);
                return;
            }

            // Unmarshal the GetRandom input
            get_random_in_unmarshal(&s->infifo, (uint8_t *)&get_random_in);

            // Execute command
            TPM_RC rc = TPM2_GetRandom(&get_random_in, &get_random_out);

            // Generate response
            if (rc != TPM_RC_SUCCESS) {
                tpm_error_response(s, rc);
            } else {
                tpm_success_response(s, (const uint8_t *)&get_random_out, sizeof(get_random_out), get_random_out_marshal);
            }

            return;

        case TPM_CC_Sign:
            {
                Sign_In sign_in;
                Sign_Out sign_out;
                
                if (cmd_header.commandSize != sizeof(tpm_cmd_header_t) + sizeof(sign_in)) {
                    tpm_error_response(s, TPM_RC_COMMAND_SIZE);
                    return;
                }

                sign_in_unmarshal(&s->infifo, (uint8_t *)&sign_in);
                TPM_RC rc = TPM2_Sign(&sign_in, &sign_out);

                if (rc != TPM_RC_SUCCESS) {
                    tpm_error_response(s, rc);
                } else {
                    tpm_success_response(s, (const uint8_t *)&sign_out, sizeof(sign_out), sign_out_marshal);
                }
            }
            return;

        case TPM_CC_VerifySignature:
            {
                VerifySignature_In verify_in;
                VerifySignature_Out verify_out;
                
                if (cmd_header.commandSize != sizeof(tpm_cmd_header_t) + sizeof(verify_in)) {
                    tpm_error_response(s, TPM_RC_COMMAND_SIZE);
                    return;
                }

                verify_signature_in_unmarshal(&s->infifo, (uint8_t *)&verify_in);
                TPM_RC rc = TPM2_VerifySignature(&verify_in, &verify_out);

                if (rc != TPM_RC_SUCCESS) {
                    tpm_error_response(s, rc);
                } else {
                    tpm_success_response(s, (const uint8_t *)&verify_out, sizeof(verify_out), verify_signature_out_marshal);
                }
            }
            return;

        case TPM_CC_Hash:
            {
                Hash_In hash_in;
                Hash_Out hash_out;
                
                if (cmd_header.commandSize != sizeof(tpm_cmd_header_t) + sizeof(hash_in)) {
                    tpm_error_response(s, TPM_RC_COMMAND_SIZE);
                    return;
                }

                hash_in_unmarshal(&s->infifo, (uint8_t *)&hash_in);
                TPM_RC rc = TPM2_Hash(&hash_in, &hash_out);

                if (rc != TPM_RC_SUCCESS) {
                    tpm_error_response(s, rc);
                } else {
                    tpm_success_response(s, (const uint8_t *)&hash_out, sizeof(hash_out), hash_out_marshal);
                }
            }
            return;

        case TPM_CC_EncryptDecrypt2:
            {
                EncryptDecrypt2_In encrypt_in;
                EncryptDecrypt2_Out encrypt_out;
                
                if (cmd_header.commandSize != sizeof(tpm_cmd_header_t) + sizeof(encrypt_in)) {
                    tpm_error_response(s, TPM_RC_COMMAND_SIZE);
                    return;
                }

                encrypt_decrypt2_in_unmarshal(&s->infifo, (uint8_t *)&encrypt_in);
                TPM_RC rc = TPM2_EncryptDecrypt2(&encrypt_in, &encrypt_out);

                if (rc != TPM_RC_SUCCESS) {
                    tpm_error_response(s, rc);
                } else {
                    tpm_success_response(s, (const uint8_t *)&encrypt_out, sizeof(encrypt_out), encrypt_decrypt2_out_marshal);
                }
            }
            return;

        case TPM_CC_RSA_Encrypt:
            {
                RSA_Encrypt_In rsa_encrypt_in;
                RSA_Encrypt_Out rsa_encrypt_out;
                
                if (cmd_header.commandSize != sizeof(tpm_cmd_header_t) + sizeof(rsa_encrypt_in)) {
                    tpm_error_response(s, TPM_RC_COMMAND_SIZE);
                    return;
                }

                rsa_encrypt_in_unmarshal(&s->infifo, (uint8_t *)&rsa_encrypt_in);
                TPM_RC rc = TPM2_RSA_Encrypt(&rsa_encrypt_in, &rsa_encrypt_out);

                if (rc != TPM_RC_SUCCESS) {
                    tpm_error_response(s, rc);
                } else {
                    tpm_success_response(s, (const uint8_t *)&rsa_encrypt_out, sizeof(rsa_encrypt_out), rsa_encrypt_out_marshal);
                }
            }
            return;

        case TPM_CC_RSA_Decrypt:
            {
                RSA_Decrypt_In rsa_decrypt_in;
                RSA_Decrypt_Out rsa_decrypt_out;
                
                if (cmd_header.commandSize != sizeof(tpm_cmd_header_t) + sizeof(rsa_decrypt_in)) {
                    tpm_error_response(s, TPM_RC_COMMAND_SIZE);
                    return;
                }

                rsa_decrypt_in_unmarshal(&s->infifo, (uint8_t *)&rsa_decrypt_in);
                TPM_RC rc = TPM2_RSA_Decrypt(&rsa_decrypt_in, &rsa_decrypt_out);

                if (rc != TPM_RC_SUCCESS) {
                    tpm_error_response(s, rc);
                } else {
                    tpm_success_response(s, (const uint8_t *)&rsa_decrypt_out, sizeof(rsa_decrypt_out), rsa_decrypt_out_marshal);
                }
            }
            return;

        default: /* unimplemented command */
            qemu_log_mask(LOG_GUEST_ERROR, "(ERROR) TPM: Unimplemented command\n");
            tpm_error_response(s, TPM_RC_COMMAND_CODE);
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

            return fifo8_pop(&s->outfifo);
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

            if (s->tpm_state == TPM_S_READY) {
                s->tpm_state = TPM_S_RECV; // Transition to receiving state
            }

            if (s->tpm_state == TPM_S_RECV) {
                fifo8_push(&s->infifo, value & 0xFF);
            }
            break;
        case A_TPM_STS:
                    
            // If commandReady is set, transition status to ready
            // Now bytes can be accepted in the input FIFO
            if (value & R_TPM_STS_commandReady_MASK) {
                if (s->tpm_state == TPM_S_CMPL) {
                    s->tpm_state = TPM_S_IDLE; // Transition to idle state
                } else {
                    s->tpm_state = TPM_S_READY;
                }
            }

            // If tpmGo is set, transition to execution state
            if (s->tpm_state == TPM_S_RECV && value & R_TPM_STS_tpmGo_MASK) {
                s->tpm_state = TPM_S_EXEC;
                s32k358_tpm_process_input(s);
            }

            break;
        default:
            qemu_log_mask(LOG_GUEST_ERROR, "%s: Bad offset 0x%"HWADDR_PRIx"\n", __func__, offset);
    }
}

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

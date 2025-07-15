#include "qemu/osdep.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "hw/sysbus.h"
#include "migration/vmstate.h"
#include "hw/irq.h"
#include "qom/object.h"
#include "qemu/log.h"
#include "include/hw/misc/s32k358_tpm.h"

/* Basic types */

#define TPM_RC_SUCCESS 0x000
#define TPM_RC_BAD_TAG 0x01E
#define RC_VER1 0x100
#define TPM_RC_COMMAND_SIZE (RC_VER1 + 0x42)
#define TPM_RC_COMMAND_CODE (RC_VER1 + 0x43)
typedef uint32_t TPM_RC;

#define TPM_ST_NO_SESSIONS 0x8001
#define TPM_ST_SESSIONS    0x8002

typedef uint16_t TPMI_ST_COMMAND_TAG;
typedef uint16_t TPM_ST;
typedef uint8_t BYTE;
typedef uint16_t UINT16;
typedef uint32_t UINT32;


#define TPM_CC_GetRandom 0x0000017B
typedef uint32_t TPM_CC;

typedef union {
    // Our hash digest types
} TPMU_HA;

typedef struct {
    UINT16 size;
    BYTE buffer[sizeof(TPMU_HA)];
} TPM2B_DIGEST;

typedef struct {
    TPMI_ST_COMMAND_TAG tag;
    UINT32 commandSize;
    TPM_CC commandCode;
} tpm_cmd_header_t;

typedef struct {
    TPM_ST tag;
    UINT32 responseSize;
    TPM_RC responseCode;
} tpm_rsp_header_t;

/* Input structures */
typedef struct {
    UINT16 bytesRequested ; // Number of random bytes requested
} GetRandom_In;

/* Output structures */
typedef struct {
    TPM2B_DIGEST randomBytes; // Random bytes generated
} GetRandom_Out;

void tpm_error_response(S32k358TPMState *s, TPM_RC rc) {
    tpm_rsp_header_t rsp_header;

    rsp_header.tag = TPM_ST_NO_SESSIONS; // No sessions for this response
    rsp_header.responseSize = sizeof(rsp_header);
    rsp_header.responseCode = rc;

    // Push the response header to the output FIFO
    fifo8_push_all(&s->outfifo, (uint8_t *)&rsp_header, sizeof(rsp_header));

    // Update status to indicate data is available
    s->tpm_state = TPM_S_CMPL; // Transition to complete state
    s->tpm_sts |= R_TPM_STS_dataAvail_MASK;
    s->tpm_sts |= R_TPM_STS_commandReady_MASK;
}

void tpm_success_response(S32k358TPMState *s, uint8_t *data, size_t size) {
    tpm_rsp_header_t rsp_header;

    rsp_header.tag = TPM_ST_NO_SESSIONS; // No sessions for this response
    rsp_header.responseSize = sizeof(rsp_header) + size;
    rsp_header.responseCode = TPM_RC_SUCCESS;

    // Push the response header to the output FIFO
    fifo8_push_all(&s->outfifo, (uint8_t *)&rsp_header, sizeof(rsp_header));

    // Push the data to the output FIFO
    fifo8_push_all(&s->outfifo, data, size);

    // Update status to indicate data is available
    s->tpm_state = TPM_S_CMPL; // Transition to complete state
    s->tpm_sts |= R_TPM_STS_dataAvail_MASK;
    s->tpm_sts |= R_TPM_STS_commandReady_MASK;
}

/* Functionalities */

TPM_RC TPM2_GetRandom (
    GetRandom_In *in, // IN: input parameter list
    GetRandom_Out *out // OUT: output parameter list
) {
    // Command Output
    // if the requested bytes exceed the output buffer size, generates the
    // maximum bytes that the output buffer allows
    if(in->bytesRequested > sizeof(TPMU_HA))
        out->randomBytes.size = sizeof(TPMU_HA);
    else
        out->randomBytes.size = in->bytesRequested;
    
    CryptRandomGenerate(out->randomBytes.size, out->randomBytes.buffer);
    
    return TPM_RC_SUCCESS;
}

/* Qemu code */

static void s32k358_tpm_process_input(S32k358TPMState *s) {
    tpm_cmd_header_t cmd_header;

    assert(s->tpm_state == TPM_S_EXEC);

    // Check if fifo is not full enough and report error condition if so
    if (fifo8_num_used(&s->infifo) < sizeof(tpm_cmd_header_t)) {
        #error "Unimplemented error handling for insufficient FIFO data"
    }

    // Unmarshal command header from FIFO
    fifo8_pop_buf(&s->infifo, (uint8_t *)&cmd_header, sizeof(cmd_header));

    // Check if tag is valid
    if (cmd_header.tag != TPM_ST_NO_SESSIONS && cmd_header.tag != TPM_ST_SESSIONS) {
        tpm_error_response(s, TPM_RC_BAD_TAG);
        return;
    }

    // Check if infifo has enough data for the command size
    if (fifo8_num_used(&s->infifo) < (cmd_header.commandSize - sizeof(tpm_cmd_header_t))) {
        tpm_error_response(s, TPM_RC_COMMAND_SIZE);
        return;
    }

    // Check if command is unimplemented
    switch (cmd_header.commandCode) {
        case TPM_CC_GetRandom:
            // Check if the command size is coherent with the expected size
            if (cmd_header.commandSize != sizeof(tpm_cmd_header_t) + sizeof(get_random_in)) {
                tpm_error_response(s, TPM_RC_COMMAND_SIZE);
                return;
            }

            // Read input parameters
            GetRandom_In get_random_in;
            GetRandom_Out get_random_out;
            fifo8_pop_buf(&s->infifo, (uint8_t *)&get_random_in, sizeof(get_random_in));

            // Execute command
            TPM_RC rc = TPM2_GetRandom(&get_random_in, &get_random_out);

            // Generate response
            if (rc != TPM_RC_SUCCESS)
                tpm_error_response(s, rc);
            else
                tpm_success_response(s,(uint8_t*)&get_random_out, sizeof(get_random_out));
            
            return;
        default: /* unimplemented command */
            tpm_error_response(s, TPM_RC_COMMAND_CODE);
            return;
    }

}

static void s32k358_tpm_update(S32k358TPMState *s) {
    if (s->tpm_access & TPM_ACCESS_requestUse) {
        // Since there's only one locality, always grant
        s->tpm_access |= TPM_ACCESS_activeLocality;
        s->tpm_access &= ~TPM_ACCESS_requestUse;
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
            s->tpm_access = value & 0xFF;
            s32k358_tpm_update(s);
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
            #warning "Some fields in TPM_STS should not be written directly, this is a simplified implementation"
            s->tpm_sts = value & 0xFFFFFFFF;
            
            // If commandReady, transition status to ready
            // Now bytes can be accepted in the input FIFO
            if (s->tpm_sts & R_TPM_STS_commandReady_MASK) {
                if (s->tpm_state == TPM_S_CMPL) {
                    s->tpm_state = TPM_S_IDLE; // Transition to idle state
                } else {
                    s->tpm_state = TPM_S_READY;
                }
                s->tpm_sts &= ~R_TPM_STS_commandReady_MASK; // Clear commandReady
            }

            if (s->tpm_state == TPM_S_RECV && s->tpm_sts & R_TPM_STS_tpmGo_MASK) {
                // If tpmGo is set, transition to execution state
                s->tpm_state = TPM_S_EXEC;
                s->tpm_sts &= ~R_TPM_STS_tpmGo_MASK; // Clear tpmGo
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

static const VMStateDescription s32k358_tpm_vmstate = {
    .name = "s32k358_tpm",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT8(status, S32k358TPMState),
        VMSTATE_UINT8(control, S32k358TPMState),
        VMSTATE_UINT8(data, S32k358TPMState),
        VMSTATE_END_OF_LIST()
    }
};

static void s32k358_tpm_reset(DeviceState *d)
{
    S32k358TPMState *s = S32K358_TPM(d);

    s->state = TPM_STATE_RST;

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

    s->state = TPM_S_IDLE; /* Ready to do stuff */
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

    dc->vmsd = &s32k358_tpm_vmstate;
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
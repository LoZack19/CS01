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
    qemu_log_mask(LOG_GUEST_ERROR, "%s: Unimplemented input processing\n", __func__);
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

    s->status = STATUS_RST;
    s->control = CONTROL_RST;
    s->data = DATA_RST;

    fifo8_reset(&s->infifo);
    fifo8_reset(&s->outfifo);
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
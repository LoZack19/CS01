#include "qemu/osdep.h"
#include "qemu/log.h"
#include "hw/char/s32k358_lpuart.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-properties-system.h"
#include "hw/sysbus.h"
#include "qemu/module.h"
#include "chardev/char-fe.h"
#include "qom/object.h"

static const MemoryRegionOps uart_ops = {
    .read = uart_read, // !TODO
    .write = uart_write, // !TODO
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4
    } // UHM???
};

static void s32k358_lpuart_realize(DeviceState *dev, Error **errp)
{
    s32k358LPUARTState *s = S32K358_LPUART(dev);

    qemu_chr_fe_set_handlers(&s->chr, lpuart_can_rx, lpuart_rx,
                             lpuart_event, NULL, s, NULL, true);
}

static void s32k358_lpuart_init(Object *obj)
{
    s32k358LPUARTState *s = S32K358_LPUART(obj);

    sysbus_init_irq(SYS_BUS_DEVICE(obj), &s->irq);

    memory_region_init_io(&s->mmio, obj, &uart_ops, s,
                          "s32k358-lpuart", R_MAX * 4);
    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->mmio);
}

static void s32k358_lpuart_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    device_class_set_legacy_reset(dc, s32k358_lpuart_reset);
    dc->realize = s32k358_lpuart_realize;
    device_class_set_props(dc, s32k358_lpuart_properties);
}

static const TypeInfo s32k358_lpuart_info = {
    .name          = TYPE_S32K358_LPUART,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(s32k358LPUARTState),
    .instance_init = s32k358_lpuart_init,
    .class_init    = s32k358_lpuart_class_init,
};

static void s32k358_lpuart_register_types(void)
{
    type_register_static(&s32k358_lpuart_info);
}

type_init(s32k358_lpuart_register_types)
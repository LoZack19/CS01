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

/**
 * documentation??
 * 
 */

static uint64_t s32k358_lpuart_read(void *opaque, hwaddr addr, unsigned int size)
{
    s32k358LPUARTState *s = S32K358_LPUART(opaque);
    switch(addr){
        case A_VERID:
            return s->verid;
        case A_STAT:
            return s->stat;
        case A_GLOBAL: 
            return s->global;
        case A_DATA:
        case A_DATARO:
            s->stat &= ~R_STAT_RDRF_MASK;
            qemu_chr_fe_accept_input(&s->chr);
            s32k358_lpuart_update_irq(s);
            return s->data;
        case A_CONTROL:
            return s->ctrl;
        case A_BAUD:
            return s->baud;
        default:
            qemu_log_mask(LOG_GUEST_ERROR,
                        "%s: Bad offset 0x%" HWADDR_PRIx "\n", __func__,
                        addr);
            return 0;
    }
}

static void s32k358_lpuart_write(void *opaque, hwaddr addr, uint64_t val64, unsigned int size){
    s32k358LPUARTState *s =  S32K358_LPUART(opaque);
    uint32_t value = val64;
    uint8_t ch;
    
    switch(addr){
        case A_GLOBAL:
            s->global = value;
            if (value & R_GLOBAL_RST_MASK) {
                s32k358_lpuart_reset(DEVICE(s));
            }
            return;
        case A_DATA:
            uint32_t is_7bit = s->ctrl & R_CTRL_M7_MASK;
            uint32_t is_9bit = s->ctrl & R_CTRL_M_MASK;

            if (is_7bit) {
                ch = value & 0x7F;
            } else if (is_9bit) {
                qemu_log_mask(LOG_GUEST_ERROR,
                    "%s: Unsupported data format" , __func__);
                return;
            } else /* 8-bit */ {
                ch = value;
            }

            qemu_chr_fe_write_all(&s->chr, &ch, 1);
            return;
        case A_CONTROL:
            s->ctrl = value
            s32k358_lpuart_update_irq(s);
            return;
        case A_BAUD:
            s->baud = value;
            s32k358_lpuart_update_params(s);
            return;
        defualt:
            qemu_log_mask(LOG_GUEST_ERROR,
                "%s: Bad offset 0x%" HWADDR_PRIx "\n", __func__,
                addr);
    }

}

static void s32k358_lpuart_reset(DeviceState *dev) {
    s32k358LPUARTState *s = S32K358_LPUART(dev);

    // s->verid ??
    // s->data ??

    s->global = GLOBAL_RST;
    s->data = DATA_RST;
    s->ctrl = CTRL_RST;
    s->baud = BAUD_RST;
    s->dataro = DATARO_RST;
    s->stat = STAT_RST;

    s32k358_lpuart_update_irq(s);
}

static void s32k358_lpuart_receive(void *opaque, const uint8_t *buf, int size) {
    s32k358LPUARTState *s = S32K358_LPUART(opaque);

    if (s->ctrl & R_CTRL_RE_MASK == 0) {
        return;
    }

    s->data = *buf;
    s->stat |= R_STAT_RDRF_MASK;
    
    s32k358_lpuart_update_irq(s);
}

static int s32k358_lpuart_can_receive(void *opaque) {
    s32k358LPUARTState *s = S32K358_LPUART(opaque);

    if (s->stat & R_STAT_RDRF_MASK) {
        return 0;
    }

    return 1;
}

static const MemoryRegionOps uart_ops = {
    .read = lpuart_read, // !TODO
    .write = lpuart_write, // !TODO
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
                          TYPE_S32K358_LPUART, 0x4000);
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
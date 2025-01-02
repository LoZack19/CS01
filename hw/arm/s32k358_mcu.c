#include "qemu/units.h"
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "hw/arm/boot.h"
#include "exec/address-spaces.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-clock.h"
#include "hw/misc/unimp.h"
#include "system/system.h"
#include "hw/arm/armv7m.h"
#include "qom/object.h"
#include "hw/clock.h"
#include "hw/arm/s32k358_mcu.h"

static void s32k358_mcu_initfn(Object *obj)
{
    S32K358State *s = S32K358_MCU(obj);
    object_initialize_child(obj, "armv7m", &s->armv7m, TYPE_ARMV7M);

    // for (int i = 0; i < STM_NUM_USARTS; i++) {
    //     object_initialize_child(obj, "usart[*]", &s->usart[i],
    //                             TYPE_STM32F2XX_USART);
    // }

    s->sysclk = qdev_init_clock_in(DEVICE(s), "sysclk", NULL, NULL, 0);
    s->refclk = qdev_init_clock_in(DEVICE(s), "refclk", NULL, NULL, 0);
}

static void create_program_flash(MyMCUState *s)
{
    MemoryRegion *sys_mem = get_system_memory();
    
    // Program flash is divided into PFC0 and PFC1 blocks
    s->flash_program = g_new(MemoryRegion, 1);
    memory_region_init_rom(s->flash_program, NULL, "program_flash", 
                          PROGRAM_FLASH_SIZE, &error_fatal);  // Total 12MB
    memory_region_add_subregion(sys_mem, 0x00400000, s->flash_program);
}

static void create_data_flash(MyMCUState *s)
{
    MemoryRegion *sys_mem = get_system_memory();
    
    s->flash_data = g_new(MemoryRegion, 1);
    memory_region_init_rom(s->flash_data, NULL, "data_flash", 
                          256 * KiB, &error_fatal);
    memory_region_add_subregion(sys_mem, 0x10000000, s->flash_data);
}

static void create_sram(S32K358State *s)
{
    MemoryRegion *sys_mem = get_system_memory();
    
    // SRAM regions with correct sizes from memory map
    const struct {
        hwaddr base;
        size_t size;
    } sram_regions[] = {
        { 0x20400000, SRAM_BLOCK_512K }, // SRAM0
        { 0x20480000, SRAM_BLOCK_512K }, // SRAM1
        { 0x20500000, SRAM_BLOCK_512K }, // SRAM2
        { 0x20580000, SRAM_BLOCK_384K }, // SRAM3
    };
    
    for (int i = 0; i < 4; i++) {
        char name[32];
        snprintf(name, sizeof(name), "sram_%d", i);
        
        s->sram[i] = g_new(MemoryRegion, 1);
        memory_region_init_ram(s->sram[i], NULL, name, sram_regions[i].size, &error_fatal);
        memory_region_add_subregion(sys_mem, sram_regions[i].base, s->sram[i]);
    }
}

static void create_unimplemented_regions(void)
{
    MemoryRegion *sys_mem = get_system_memory();
    
    // ITCM regions (4 x 64KB at same address)
    for (int i = 0; i < 4; i++) {
        char name[32];
        snprintf(name, sizeof(name), "itcm_%d", i);
        MemoryRegion *itcm = g_new(MemoryRegion, 1);
        memory_region_init_io(itcm, NULL, NULL, NULL, name, ITCM_SIZE);
        memory_region_add_subregion_overlap(sys_mem, 0x00000000, itcm, i);
    }
    
    // ITCM backdoor regions (4 x 64KB at different addresses)
    for (int i = 0; i < 4; i++) {
        char name[32];
        snprintf(name, sizeof(name), "itcm_%d_backdoor", i);
        MemoryRegion *itcm_backdoor = g_new(MemoryRegion, 1);
        memory_region_init_io(itcm_backdoor, NULL, NULL, NULL, name, ITCM_SIZE);
        memory_region_add_subregion(sys_mem, 0x11000000 + (i * 0x400000), itcm_backdoor);
    }
    
    // DTCM regions (4 x 128KB at same address)
    for (int i = 0; i < 4; i++) {
        char name[32];
        snprintf(name, sizeof(name), "dtcm_%d", i);
        MemoryRegion *dtcm = g_new(MemoryRegion, 1);
        memory_region_init_io(dtcm, NULL, NULL, NULL, name, DTCM_SIZE);
        memory_region_add_subregion_overlap(sys_mem, 0x20000000, dtcm, i);
    }
    
    // DTCM backdoor regions (4 x 128KB at different addresses)
    for (int i = 0; i < 4; i++) {
        char name[32];
        snprintf(name, sizeof(name), "dtcm_%d_backdoor", i);
        MemoryRegion *dtcm_backdoor = g_new(MemoryRegion, 1);
        memory_region_init_io(dtcm_backdoor, NULL, NULL, NULL, name, DTCM_SIZE);
        memory_region_add_subregion(sys_mem, 0x21000000 + (i * 0x400000), dtcm_backdoor);
    }
    
    // UTEST region (8KB)
    MemoryRegion *utest = g_new(MemoryRegion, 1);
    memory_region_init_io(utest, NULL, NULL, NULL, "utest", 8 * KiB);
    memory_region_add_subregion(sys_mem, 0x1B000000, utest);
    
    // AIPS regions
    MemoryRegion *aips0 = g_new(MemoryRegion, 1);
    memory_region_init_io(aips0, NULL, NULL, NULL, "aips0", 2 * MiB);
    memory_region_add_subregion(sys_mem, 0x40000000, aips0);

    MemoryRegion *aips1 = g_new(MemoryRegion, 1);
    memory_region_init_io(aips1, NULL, NULL, NULL, "aips1", 2 * MiB);
    memory_region_add_subregion(sys_mem, 0x40200000, aips1);

    MemoryRegion *aips2 = g_new(MemoryRegion, 1);
    memory_region_init_io(aips2, NULL, NULL, NULL, "aips2", 2 * MiB);
    memory_region_add_subregion(sys_mem, 0x40400000, aips2);

    // Additional peripheral regions
    MemoryRegion *aes = g_new(MemoryRegion, 1);
    memory_region_init_io(aes, NULL, NULL, NULL, "aes_accel", 1 * KiB);
    memory_region_add_subregion(sys_mem, 0x44000000, aes);

    MemoryRegion *qspi_rx = g_new(MemoryRegion, 1);
    memory_region_init_io(qspi_rx, NULL, NULL, NULL, "qspi_rx", 1 * KiB);
    memory_region_add_subregion(sys_mem, 0x67000000, qspi_rx);

    MemoryRegion *qspi_ahb = g_new(MemoryRegion, 1);
    memory_region_init_io(qspi_ahb, NULL, NULL, NULL, "qspi_ahb", 128 * MiB);
    memory_region_add_subregion(sys_mem, 0x68000000, qspi_ahb);

    MemoryRegion *ppb = g_new(MemoryRegion, 1);
    memory_region_init_io(ppb, NULL, NULL, NULL, "ppb", 1 * MiB);
    memory_region_add_subregion(sys_mem, 0xE0000000, ppb);
}

static void s32k358_mcu_realize(DeviceState *dev_soc, Error **errp)
{
    S32K358State *s = S32K358_MCU(dev_soc);
    DeviceState *armv7m;

    /*
     * We use s->refclk internally and only define it with qdev_init_clock_in()
     * so it is correctly parented and not leaked on an init/deinit; it is not
     * intended as an externally exposed clock.
     */
    if (clock_has_source(s->refclk)) {
        error_setg(errp, "refclk clock must not be wired up by the board code");
        return;
    }

    if (!clock_has_source(s->sysclk)) {
        error_setg(errp, "sysclk clock must be wired up by the board code");
        return;
    }

    /*
     * TODO: ideally we should model the SoC RCC and its ability to
     * change the sysclk frequency and define different sysclk sources.
     */

    /* The refclk always runs at frequency HCLK / 8 */
    clock_set_mul_div(s->refclk, 8, 1);
    clock_set_source(s->refclk, s->sysclk);

    // Initialize implemented memory regions
    create_program_flash(s);
    create_data_flash(s);
    create_sram(s);
    
    // Create all unimplemented device regions
    create_unimplemented_regions();

    /* Init ARMv7m */
    armv7m = DEVICE(&s->armv7m);
    qdev_prop_set_uint32(armv7m, "num-irq", 240);
    qdev_prop_set_uint8(armv7m, "num-prio-bits", 4);
    qdev_prop_set_string(armv7m, "cpu-type", ARM_CPU_TYPE_NAME("cortex-m7"));
    qdev_prop_set_uint32(armv7m, "init-svtor", PROGRAM_FLASH_BASE_ADDRESS);
    qdev_prop_set_uint32(armv7m, "init-nsvtor", PROGRAM_FLASH_BASE_ADDRESS);
    qdev_prop_set_bit(armv7m, "enable-bitband", true);
    qdev_connect_clock_in(armv7m, "cpuclk", s->sysclk);
    qdev_connect_clock_in(armv7m, "refclk", s->refclk);
    object_property_set_link(OBJECT(&s->armv7m), "memory",
                             OBJECT(get_system_memory()), &error_abort);
    if (!sysbus_realize(SYS_BUS_DEVICE(&s->armv7m), errp)) {
        return;
    }

    /* Attach UART (uses USART registers) and USART controllers */
    // for (int i = 0; i < STM_NUM_USARTS; i++) {
    //     dev = DEVICE(&(s->usart[i]));
    //     qdev_prop_set_chr(dev, "chardev", serial_hd(i));
    //     if (!sysbus_realize(SYS_BUS_DEVICE(&s->usart[i]), errp)) {
    //         return;
    //     }
    //     busdev = SYS_BUS_DEVICE(dev);
    //     sysbus_mmio_map(busdev, 0, usart_addr[i]);
    //     sysbus_connect_irq(busdev, 0, qdev_get_gpio_in(armv7m, usart_irq[i]));
    // }

    // create_unimplemented_device("timer[2]",  0x40000000, 0x400);
    // create_unimplemented_device("timer[3]",  0x40000400, 0x400);
    // create_unimplemented_device("timer[4]",  0x40000800, 0x400);
    // create_unimplemented_device("timer[6]",  0x40001000, 0x400);
    // create_unimplemented_device("timer[7]",  0x40001400, 0x400);
    // create_unimplemented_device("RTC",       0x40002800, 0x400);
    // create_unimplemented_device("WWDG",      0x40002C00, 0x400);
    // create_unimplemented_device("IWDG",      0x40003000, 0x400);
    // create_unimplemented_device("I2C1",      0x40005400, 0x400);
    // create_unimplemented_device("I2C2",      0x40005800, 0x400);
    // create_unimplemented_device("BKP",       0x40006C00, 0x400);
    // create_unimplemented_device("PWR",       0x40007000, 0x400);
    // create_unimplemented_device("DAC",       0x40007400, 0x400);
    // create_unimplemented_device("CEC",       0x40007800, 0x400);
    // create_unimplemented_device("AFIO",      0x40010000, 0x400);
    // create_unimplemented_device("EXTI",      0x40010400, 0x400);
    // create_unimplemented_device("GPIOA",     0x40010800, 0x400);
    // create_unimplemented_device("GPIOB",     0x40010C00, 0x400);
    // create_unimplemented_device("GPIOC",     0x40011000, 0x400);
    // create_unimplemented_device("GPIOD",     0x40011400, 0x400);
    // create_unimplemented_device("GPIOE",     0x40011800, 0x400);
    // create_unimplemented_device("ADC1",      0x40012400, 0x400);
    // create_unimplemented_device("timer[1]",  0x40012C00, 0x400);
    // create_unimplemented_device("timer[15]", 0x40014000, 0x400);
    // create_unimplemented_device("timer[16]", 0x40014400, 0x400);
    // create_unimplemented_device("timer[17]", 0x40014800, 0x400);
    // create_unimplemented_device("DMA",       0x40020000, 0x400);
    // create_unimplemented_device("RCC",       0x40021000, 0x400);
    // create_unimplemented_device("Flash Int", 0x40022000, 0x400);
    // create_unimplemented_device("CRC",       0x40023000, 0x400);
}

static void s32k358_mcu_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = s32k358_mcu_realize;
    /* No vmstate or reset required: device has no internal state */
}

static const TypeInfo s32k358_mcu_info = {
    .name          = TYPE_S32K358_MCU,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(S32K358State),
    .instance_init = s32k358_mcu_initfn,
    .class_init    = s32k358_mcu_class_init,
};

static void s32k358_mcu_types(void)
{
    type_register_static(&s32k358_mcu_info);
}

type_init(s32k358_mcu_types)
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

#define ALIGN_OFFSET 8192

#define MC_ME_BASE_ADDRESS 0x402dc000
#define MC_ME_SIZE 1340

static uint64_t mc_me_read(void *opaque, hwaddr addr, unsigned size) {
    uint32_t ret = 0;

    switch (addr) {
        case 0x310:
            ret = 0x1000000;
            break;
        default:
            ret = 0x0;
            break;
    }

    return ret;
}

static void mc_me_write(void *opaque, hwaddr addr, uint64_t val,
                        unsigned size) {
    switch (addr) {
        default:
            break;
    }
}

static const MemoryRegionOps mc_me_ops = {
    .read = mc_me_read,
    .write = mc_me_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static void s32k358_mcu_initfn(Object *obj)
{
    S32K358State *s = S32K358_MCU(obj);
    object_initialize_child(obj, "armv7m", &s->armv7m, TYPE_ARMV7M);
    
    s->sysclk = qdev_init_clock_in(DEVICE(s), "sysclk", NULL, NULL, 0);
    s->refclk = qdev_init_clock_in(DEVICE(s), "refclk", NULL, NULL, 0);
    s->aips_plat_clk = qdev_init_clock_in(DEVICE(s), "aips_plat_clk", NULL, NULL, 0);
    s->aips_slow_clk = qdev_init_clock_in(DEVICE(s), "aips_slow_clk", NULL, NULL, 0);

    for (int i = 0; i < S32K358_NUM_LPUART; i++) {
        object_initialize_child(obj, "lpuart[*]", &s->lpuart[i],
                                TYPE_S32K358_LPUART);
    }
}

static void create_program_flash(S32K358State *s)
{
    MemoryRegion *sys_mem = get_system_memory();
    
    memory_region_init_rom(&s->flash_program, NULL, "program_flash", 
                          PROGRAM_FLASH_SIZE, &error_fatal);  // Total 12MB
    memory_region_add_subregion(sys_mem, PROGRAM_FLASH_BASE_ADDRESS, &s->flash_program);
}

static void create_data_flash(S32K358State *s)
{
    MemoryRegion *sys_mem = get_system_memory();
    
    memory_region_init_rom(&s->flash_data, NULL, "data_flash", 
                          256 * KiB, &error_fatal);
    memory_region_add_subregion(sys_mem, 0x10000000, &s->flash_data);
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
        
        memory_region_init_ram(&s->sram[i], NULL, name, sram_regions[i].size, &error_fatal);
        memory_region_add_subregion(sys_mem, sram_regions[i].base, &s->sram[i]);
    }
}

static void create_itcm(S32K358State *s) {
    MemoryRegion *sys_mem = get_system_memory();

    const struct {
        hwaddr base;
        size_t size;
    } itcm_regions[] = {
        { 0x00000000, ITCM_SIZE },
    };
    
    memory_region_init_ram(&s->itcm, NULL, "itcm", itcm_regions[0].size, &error_fatal);
    memory_region_add_subregion(sys_mem, itcm_regions[0].base, &s->itcm);
}

static void create_dtcm(S32K358State *s)
{
    MemoryRegion *sys_mem = get_system_memory();

    const struct {
        hwaddr base;
        size_t size;
    } dtcm_regions[] = {
        { 0x20000000, DTCM_SIZE },
    };

    memory_region_init_ram(&s->dtcm, NULL, "dtcm", dtcm_regions[0].size, &error_fatal);
    memory_region_add_subregion(sys_mem, dtcm_regions[0].base, &s->dtcm);
}

// Attach UART (uses USART registers) and USART controllers
static void create_lpuart(S32K358State *s, DeviceState *armv7m, Error **errp)
{
    DeviceState *dev;
    SysBusDevice *busdev;

    for (int i = 0; i < S32K358_NUM_LPUART; i++) {
        dev = DEVICE(&(s->lpuart[i]));
        qdev_prop_set_chr(dev, "chardev", serial_hd(i));

        // Connect the LPUART to the appropriate clock
        if (i == 0 || i == 1 || i == 8) {
            qdev_connect_clock_in(dev, "clk", s->aips_plat_clk);
        } else {
            qdev_connect_clock_in(dev, "clk", s->aips_slow_clk);
        }

        if (!sysbus_realize(SYS_BUS_DEVICE(dev), errp)) {
            return;
        }

        busdev = SYS_BUS_DEVICE(dev);
        sysbus_mmio_map(busdev, 0, lpuart_addr[i]);
        sysbus_connect_irq(busdev, 0, qdev_get_gpio_in(armv7m, lpuart_irq[i]));
    }
}

static void tpm_wire_to_board(ARMv7MState *armv7m, S32K358TPMState *tpm, Error **errp) {
    DeviceState *armv7mdev = DEVICE(armv7m);
    DeviceState *tpmdev = DEVICE(tpm);
    SysBusDevice *busdev = SYS_BUS_DEVICE(tpmdev);

    if (!sysbus_realize(busdev, errp))
        return;

    sysbus_mmio_map(busdev, 0, TPM_TIS_LOC0);
}

static void s32k358_mcu_realize(DeviceState *dev_soc, Error **errp)
{
    S32K358State *s = S32K358_MCU(dev_soc);
    DeviceState *armv7m;
    MemoryRegion *sys_mem = get_system_memory();

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

    clock_set_hz(s->aips_plat_clk, 80000000);
    clock_set_hz(s->aips_plat_clk, 40000000);

    // Initialize implemented memory regions
    create_itcm(s);
    create_dtcm(s);
    create_program_flash(s);
    create_data_flash(s);
    create_sram(s);

    // Connect MC_ME
    memory_region_init_io(&s->mc_me, OBJECT(dev_soc), &mc_me_ops, s, "NXPS32K358.MC_ME", MC_ME_SIZE);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->mc_me);
    memory_region_add_subregion(sys_mem, MC_ME_BASE_ADDRESS, &s->mc_me);

    // Init ARMv7m
    armv7m = DEVICE(&s->armv7m);
    qdev_prop_set_uint32(armv7m, "num-irq", 240);
    qdev_prop_set_uint8(armv7m, "num-prio-bits", 4);
    qdev_prop_set_string(armv7m, "cpu-type", ARM_CPU_TYPE_NAME("cortex-m7"));
    qdev_prop_set_uint32(armv7m, "init-svtor", PROGRAM_FLASH_BASE_ADDRESS + ALIGN_OFFSET);
    qdev_prop_set_uint32(armv7m, "init-nsvtor", PROGRAM_FLASH_BASE_ADDRESS + ALIGN_OFFSET);
    qdev_prop_set_uint32(armv7m, "mpu-ns-regions", 16);
    qdev_prop_set_uint32(armv7m, "mpu-s-regions", 16);
    qdev_prop_set_bit(armv7m, "enable-bitband", true);
    qdev_connect_clock_in(armv7m, "cpuclk", s->sysclk);
    qdev_connect_clock_in(armv7m, "refclk", s->refclk);
    object_property_set_link(OBJECT(&s->armv7m), "memory",
                             OBJECT(get_system_memory()), &error_abort);
    if (!sysbus_realize(SYS_BUS_DEVICE(&s->armv7m), errp)) {
        return;
    }

    create_lpuart(s, armv7m, errp);
    tpm_wire_to_board(&armv7m, &s->tpm, errp);

    create_unimplemented_device("hse_xbic", 0x40008000, 0x4000);
    create_unimplemented_device("erm1", 0x4000c000, 0x4000);
    create_unimplemented_device("pfc1", 0x40068000, 0x4000);
    create_unimplemented_device("pfc1_alt", 0x4006c000, 0x4000);
    create_unimplemented_device("swt_3", 0x40070000, 0x4000);
    create_unimplemented_device("trgmux", 0x40080000, 0x4000);
    create_unimplemented_device("bctu", 0x40084000, 0x4000);
    create_unimplemented_device("emios0", 0x40088000, 0x4000);
    create_unimplemented_device("emios1", 0x4008c000, 0x4000);
    create_unimplemented_device("emios2", 0x40090000, 0x4000);
    create_unimplemented_device("lcu0", 0x40098000, 0x4000);
    create_unimplemented_device("lcu1", 0x4009c000, 0x4000);
    create_unimplemented_device("adc_0", 0x400a0000, 0x4000);
    create_unimplemented_device("adc_1", 0x400a4000, 0x4000);
    create_unimplemented_device("adc_2", 0x400a8000, 0x4000);
    create_unimplemented_device("pit0", 0x400b0000, 0x4000);
    create_unimplemented_device("pit1", 0x400b4000, 0x4000);
    create_unimplemented_device("mu_2", 0x400b8000, 0x4000);
    create_unimplemented_device("mu_2", 0x400bc000, 0x4000);
    create_unimplemented_device("mu_3", 0x400c4000, 0x4000);
    create_unimplemented_device("mu_3", 0x400c8000, 0x4000);
    create_unimplemented_device("mu_4", 0x400cc000, 0x4000);
    create_unimplemented_device("mu_4", 0x400d0000, 0x4000);
    create_unimplemented_device("axbs", 0x40200000, 0x4000);
    create_unimplemented_device("system_xbic", 0x40204000, 0x4000);
    create_unimplemented_device("periph_xbic", 0x40208000, 0x4000);
    create_unimplemented_device("edma", 0x4020c000, 0x4000);
    create_unimplemented_device("edma_tcd_0", 0x40210000, 0x4000);
    create_unimplemented_device("edma_tcd_1", 0x40214000, 0x4000);
    create_unimplemented_device("edma_tcd_2", 0x40218000, 0x4000);
    create_unimplemented_device("edma_tcd_3", 0x4021c000, 0x4000);
    create_unimplemented_device("edma_tcd_4", 0x40220000, 0x4000);
    create_unimplemented_device("edma_tcd_5", 0x40224000, 0x4000);
    create_unimplemented_device("edma_tcd_6", 0x40228000, 0x4000);
    create_unimplemented_device("edma_tcd_7", 0x4022c000, 0x4000);
    create_unimplemented_device("edma_tcd_8", 0x40230000, 0x4000);
    create_unimplemented_device("edma_tcd_9", 0x40234000, 0x4000);
    create_unimplemented_device("edma_tcd_10", 0x40238000, 0x4000);
    create_unimplemented_device("edma_tcd_11", 0x4023c000, 0x4000);
    create_unimplemented_device("debug_apb_page0", 0x40240000, 0x4000);
    create_unimplemented_device("debug_apb_page1", 0x40244000, 0x4000);
    create_unimplemented_device("debug_apb_page2", 0x40248000, 0x4000);
    create_unimplemented_device("debug_apb_page3", 0x4024c000, 0x4000);
    create_unimplemented_device("debug_apb_paged_area", 0x40250000, 0x4000);
    create_unimplemented_device("sda-ap", 0x40254000, 0x4000);
    create_unimplemented_device("eim0", 0x40258000, 0x4000);
    create_unimplemented_device("erm0", 0x4025c000, 0x4000);
    create_unimplemented_device("mscm", 0x40260000, 0x4000);
    create_unimplemented_device("pram_0", 0x40264000, 0x4000);
    create_unimplemented_device("pfc", 0x40268000, 0x4000);
    create_unimplemented_device("pfc_alt", 0x4026c000, 0x4000);
    create_unimplemented_device("swt_0", 0x40270000, 0x4000);
    create_unimplemented_device("stm_0", 0x40274000, 0x4000);
    create_unimplemented_device("xrdc", 0x40278000, 0x4000);
    create_unimplemented_device("intm", 0x4027c000, 0x4000);
    create_unimplemented_device("dmamux_0", 0x40280000, 0x4000);
    create_unimplemented_device("dmamux_1", 0x40284000, 0x4000);
    create_unimplemented_device("rtc", 0x40288000, 0x4000);
    create_unimplemented_device("mc_rgm", 0x4028c000, 0x4000);
    create_unimplemented_device("siul_virtwrapper_pdac0_hse", 0x40290000, 0x4000);
    create_unimplemented_device("siul_virtwrapper_pdac0_hse", 0x40294000, 0x4000);
    create_unimplemented_device("siul_virtwrapper_pdac1_m7_0", 0x40298000, 0x4000);
    create_unimplemented_device("siul_virtwrapper_pdac1_m7_0", 0x4029c000, 0x4000);
    create_unimplemented_device("siul_virtwrapper_pdac2_m7_1", 0x402a0000, 0x4000);
    create_unimplemented_device("siul_virtwrapper_pdac2_m7_1", 0x402a4000, 0x4000);
    create_unimplemented_device("siul_virtwrapper_pdac3", 0x402a8000, 0x4000);
    create_unimplemented_device("dcm", 0x402ac000, 0x4000);
    create_unimplemented_device("wkpu", 0x402b4000, 0x4000);
    create_unimplemented_device("cmu", 0x402bc000, 0x4000);
    create_unimplemented_device("tspc", 0x402c4000, 0x4000);
    create_unimplemented_device("sirc", 0x402c8000, 0x4000);
    create_unimplemented_device("sxosc", 0x402cc000, 0x4000);
    create_unimplemented_device("firc", 0x402d0000, 0x4000);
    create_unimplemented_device("fxosc", 0x402d4000, 0x4000);
    create_unimplemented_device("mc_cgm", 0x402d8000, 0x4000);
    create_unimplemented_device("mc_me", 0x402dc000, 0x4000);
    create_unimplemented_device("pll", 0x402e0000, 0x4000);
    create_unimplemented_device("pll2", 0x402e4000, 0x4000);
    create_unimplemented_device("pmc", 0x402e8000, 0x4000);
    create_unimplemented_device("fmu", 0x402ec000, 0x4000);
    create_unimplemented_device("fmu_alt", 0x402f0000, 0x4000);
    create_unimplemented_device("siul_virtwrapper_pdac4_m7_2", 0x402f4000, 0x4000);
    create_unimplemented_device("siul_virtwrapper_pdac4_m7_2", 0x402f8000, 0x4000);
    create_unimplemented_device("pit2", 0x402fc000, 0x4000);
    create_unimplemented_device("pit3", 0x40300000, 0x4000);
    create_unimplemented_device("flexcan_0", 0x40304000, 0x4000);
    create_unimplemented_device("flexcan_1", 0x40308000, 0x4000);
    create_unimplemented_device("flexcan_2", 0x4030c000, 0x4000);
    create_unimplemented_device("flexcan_3", 0x40310000, 0x4000);
    create_unimplemented_device("flexcan_4", 0x40314000, 0x4000);
    create_unimplemented_device("flexcan_5", 0x40318000, 0x4000);
    create_unimplemented_device("flexcan_6", 0x4031c000, 0x4000);
    create_unimplemented_device("flexcan_7", 0x40320000, 0x4000);
    create_unimplemented_device("flexio", 0x40324000, 0x4000);
    create_unimplemented_device("lpuart_0", 0x40328000, 0x4000);
    create_unimplemented_device("lpuart_1", 0x4032c000, 0x4000);
    create_unimplemented_device("lpuart_2", 0x40330000, 0x4000);
    create_unimplemented_device("lpuart_3", 0x40334000, 0x4000);
    create_unimplemented_device("lpuart_4", 0x40338000, 0x4000);
    create_unimplemented_device("lpuart_5", 0x4033c000, 0x4000);
    create_unimplemented_device("lpuart_6", 0x40340000, 0x4000);
    create_unimplemented_device("lpuart_7", 0x40344000, 0x4000);
    create_unimplemented_device("siul_virtwrapper_pdac5_m7_3", 0x40348000, 0x4000);
    create_unimplemented_device("siul_virtwrapper_pdac5_m7_3", 0x4034c000, 0x4000);
    create_unimplemented_device("lpi2c_0", 0x40350000, 0x4000);
    create_unimplemented_device("lpi2c_1", 0x40354000, 0x4000);
    create_unimplemented_device("lpspi_0", 0x40358000, 0x4000);
    create_unimplemented_device("lpspi_1", 0x4035c000, 0x4000);
    create_unimplemented_device("lpspi_2", 0x40360000, 0x4000);
    create_unimplemented_device("lpspi_3", 0x40364000, 0x4000);
    create_unimplemented_device("sai0", 0x4036c000, 0x4000);
    create_unimplemented_device("lpcmp_0", 0x40370000, 0x4000);
    create_unimplemented_device("lpcmp_1", 0x40374000, 0x4000);
    create_unimplemented_device("tmu", 0x4037c000, 0x4000);
    create_unimplemented_device("crc", 0x40380000, 0x4000);
    create_unimplemented_device("fccu_", 0x40384000, 0x4000);
    create_unimplemented_device("mu_0", 0x4038c000, 0x4000);
    create_unimplemented_device("mu_1", 0x40390000, 0x4000);
    create_unimplemented_device("jdc", 0x40394000, 0x4000);
    create_unimplemented_device("configuration_gpr", 0x4039c000, 0x4000);
    create_unimplemented_device("stcu", 0x403a0000, 0x4000);
    create_unimplemented_device("selftest_gpr", 0x403b0000, 0x4000);
    create_unimplemented_device("aes_accel", 0x403c0000, 0x10000);
    create_unimplemented_device("aes_app0", 0x403d0000, 0x10000);
    create_unimplemented_device("aes_app1", 0x403e0000, 0x10000);
    create_unimplemented_device("aes_app2", 0x403f0000, 0x10000);
    create_unimplemented_device("tcm_xbic", 0x40400000, 0x4000);
    create_unimplemented_device("edma_xbic", 0x40404000, 0x4000);
    create_unimplemented_device("pram2_tcm_xbic", 0x40408000, 0x4000);
    create_unimplemented_device("aes_mux_xbic", 0x4040c000, 0x4000);
    create_unimplemented_device("edma_tcd_12", 0x40410000, 0x4000);
    create_unimplemented_device("edma_tcd_13", 0x40414000, 0x4000);
    create_unimplemented_device("edma_tcd_14", 0x40418000, 0x4000);
    create_unimplemented_device("edma_tcd_15", 0x4041c000, 0x4000);
    create_unimplemented_device("edma_tcd_16", 0x40420000, 0x4000);
    create_unimplemented_device("edma_tcd_17", 0x40424000, 0x4000);
    create_unimplemented_device("edma_tcd_18", 0x40428000, 0x4000);
    create_unimplemented_device("edma_tcd_19", 0x4042c000, 0x4000);
    create_unimplemented_device("edma_tcd_20", 0x40430000, 0x4000);
    create_unimplemented_device("edma_tcd_21", 0x40434000, 0x4000);
    create_unimplemented_device("edma_tcd_22", 0x40438000, 0x4000);
    create_unimplemented_device("edma_tcd_23", 0x4043c000, 0x4000);
    create_unimplemented_device("edma_tcd_24", 0x40440000, 0x4000);
    create_unimplemented_device("edma_tcd_25", 0x40444000, 0x4000);
    create_unimplemented_device("edma_tcd_26", 0x40448000, 0x4000);
    create_unimplemented_device("edma_tcd_27", 0x4044c000, 0x4000);
    create_unimplemented_device("edma_tcd_28", 0x40450000, 0x4000);
    create_unimplemented_device("edma_tcd_29", 0x40454000, 0x4000);
    create_unimplemented_device("edma_tcd_30", 0x40458000, 0x4000);
    create_unimplemented_device("edma_tcd_31", 0x4045c000, 0x4000);
    create_unimplemented_device("sema42", 0x40460000, 0x4000);
    create_unimplemented_device("pram_1", 0x40464000, 0x4000);
    create_unimplemented_device("pram_2", 0x40468000, 0x4000);
    create_unimplemented_device("swt_1", 0x4046c000, 0x4000);
    create_unimplemented_device("swt_2", 0x40470000, 0x4000);
    create_unimplemented_device("stm_1", 0x40474000, 0x4000);
    create_unimplemented_device("stm_2", 0x40478000, 0x4000);
    create_unimplemented_device("stm_3", 0x4047c000, 0x4000);
    create_unimplemented_device("emac", 0x40480000, 0x4000);
    create_unimplemented_device("gmac0", 0x40484000, 0x4000);
    create_unimplemented_device("gmac1", 0x40488000, 0x4000);
    create_unimplemented_device("lpuart_8", 0x4048c000, 0x4000);
    create_unimplemented_device("lpuart_9", 0x40490000, 0x4000);
    create_unimplemented_device("lpuart_10", 0x40494000, 0x4000);
    create_unimplemented_device("lpuart_11", 0x40498000, 0x4000);
    create_unimplemented_device("lpuart_12", 0x4049c000, 0x4000);
    create_unimplemented_device("lpuart_13", 0x404a0000, 0x4000);
    create_unimplemented_device("lpuart_14", 0x404a4000, 0x4000);
    create_unimplemented_device("lpuart_15", 0x404a8000, 0x4000);
    create_unimplemented_device("lpspi_4", 0x404bc000, 0x4000);
    create_unimplemented_device("lpspi_5", 0x404c0000, 0x4000);
    create_unimplemented_device("quadspi", 0x404cc000, 0x4000);
    create_unimplemented_device("sai1", 0x404dc000, 0x4000);
    create_unimplemented_device("usdhc", 0x404e4000, 0x4000);
    create_unimplemented_device("lpcmp_2", 0x404e8000, 0x4000);
    create_unimplemented_device("mu_1", 0x404ec000, 0x4000);
    create_unimplemented_device("eim0", 0x4050c000, 0x4000);
    create_unimplemented_device("eim1", 0x40510000, 0x4000);
    create_unimplemented_device("eim2", 0x40514000, 0x4000);
    create_unimplemented_device("eim3", 0x40518000, 0x4000);
    create_unimplemented_device("aes_app3", 0x40520000, 0x10000);
    create_unimplemented_device("aes_app4", 0x40530000, 0x10000);
    create_unimplemented_device("aes_app5", 0x40540000, 0x10000);
    create_unimplemented_device("aes_app6", 0x40550000, 0x10000);
    create_unimplemented_device("aes_app7", 0x40560000, 0x10000);
    create_unimplemented_device("flexcan_8", 0x40570000, 0x4000);
    create_unimplemented_device("flexcan_9", 0x40574000, 0x4000);
    create_unimplemented_device("flexcan_10", 0x40578000, 0x4000);
    create_unimplemented_device("flexcan_11", 0x4057c000, 0x4000);
    create_unimplemented_device("fmu1", 0x40580000, 0x4000);
    create_unimplemented_device("fmu1_alt", 0x40584000, 0x4000);
    create_unimplemented_device("pram_3", 0x40588000, 0x4000);
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

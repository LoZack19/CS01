#ifndef S32K358_MCU_H
#define S32K358_MCU_H

#include "hw/arm/armv7m.h"
#include "qemu/typedefs.h"
#include "qom/object.h"
#include "hw/char/s32k358_lpuart.h"
#include "include/qemu/units.h"
#include "hw/misc/s32k358_tpm.h"

#define ITCM_SIZE (64 * KiB)
#define DTCM_SIZE (128 * KiB)
#define FLASH_BLOCK_2048K (2048 * KiB)
#define FLASH_BLOCK_1024K (1024 * KiB)
#define FLASH_BLOCK_512K (512 * KiB)
#define SRAM_BLOCK_512K (512 * KiB)
#define SRAM_BLOCK_384K (384 * KiB)
#define SRAM_BLOCK_256K (256 * KiB)
#define SRAM_BLOCK_160K (160 * KiB)

#define PROGRAM_FLASH_BASE_ADDRESS 0x00400000
#define PROGRAM_FLASH_SIZE 8 * MiB

#define S32K358_NUM_LPUART 16

#define TPM_TIS_LOC0 0x40000000

static const hwaddr lpuart_addr[] = {
    0x40328000, // lpuart[0]
    0x4032c000, // lpuart[1]
    0x40330000, // lpuart[2]
    0x40334000, // lpuart[3]
    0x40338000, // lpuart[4]
    0x4033c000, // lpuart[5]
    0x40340000, // lpuart[6]
    0x40344000, // lpuart[7]
    0x4048c000, // lpuart[8]
    0x40490000, // lpuart[9]
    0x40494000, // lpuart[10]
    0x40498000, // lpuart[11]
    0x4049c000, // lpuart[12]
    0x404a0000, // lpuart[13]
    0x404a4000, // lpuart[14]
    0x404a8000, // lpuart[15]
};

static const int lpuart_irq[] = {141, 142, 143, 144, 145, 146, 147, 148,
                                149, 150, 151, 152, 153, 154, 155, 156};

#define TYPE_S32K358_MCU "s32k358_mcu"
OBJECT_DECLARE_SIMPLE_TYPE(S32K358State, S32K358_MCU)

struct S32K358State {
    SysBusDevice parent_obj;

    ARMv7MState armv7m;
    
    // Only keep implemented memory regions
    MemoryRegion itcm;
    MemoryRegion dtcm;
    MemoryRegion flash_program;
    MemoryRegion flash_data;
    MemoryRegion sram[4];
    MemoryRegion mc_me;
    
    s32k358LPUARTState lpuart[S32K358_NUM_LPUART];

    S32k358TPMState tpm;

    Clock *sysclk;
    Clock *refclk;
    Clock *aips_plat_clk;
    Clock *aips_slow_clk; 
};

#endif

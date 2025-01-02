#ifndef S32K358_MCU_H
#define S32K358_MCU_H

#include "hw/arm/armv7m.h"
#include "qemu/typedefs.h"
#include "qom/object.h"
#include "include/qemu/units.h"

#define ITCM_SIZE (64 * KiB)
#define DTCM_SIZE (128 * KiB)
#define FLASH_BLOCK_2048K (2048 * KiB)
#define FLASH_BLOCK_1024K (1024 * KiB)
#define FLASH_BLOCK_512K (512 * KiB)
#define SRAM_BLOCK_512K (512 * KiB)
#define SRAM_BLOCK_384K (384 * KiB)
#define SRAM_BLOCK_256K (256 * KiB)
#define SRAM_BLOCK_160K (160 * KiB)

#define PROGRAM_FLASH_BASE_ADDRESS 0x00800000
#define PROGRAM_FLASH_SIZE 8 * MiB

#define TYPE_S32K358_MCU "s32k358_mcu"
OBJECT_DECLARE_SIMPLE_TYPE(S32K358State, S32K358_MCU)

typedef struct S32K358State {
    SysBusDevice parent_obj;

    ARMv7MState armv7m;
    
    // Only keep implemented memory regions
    MemoryRegion itcm;
    MemoryRegion dtcm;
    MemoryRegion flash_program;
    MemoryRegion flash_data;
    MemoryRegion sram[4];

    Clock *sysclk;
    Clock *refclk;
    
} MyMCUState;

#endif